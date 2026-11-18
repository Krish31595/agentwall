"""Automatic AI-threat detection with auto-quarantine.

Every egress attempt and model request is fed to the `ThreatEngine`. Detectors
add risk points to the agent's segment. Points decay over time. When a segment
crosses `quarantine_score`, it is quarantined: all egress and model calls are
denied until the quarantine expires or a human releases it.

Blocking is deterministic on purpose. An LLM may *explain* an alert
(see advisor.triage), but it can never lift a block, so a prompt injection
cannot talk the guard out of stopping an attack.
"""
from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

from .audit import AuditLog

# Destinations commonly used to smuggle data out or to open tunnels.
EXFIL_HOST_GLOBS = [
    "pastebin.com", "*.pastebin.com", "paste.ee", "hastebin.com", "ghostbin.*", "dpaste.*", "rentry.co",
    "transfer.sh", "*.transfer.sh", "file.io", "0x0.st", "temp.sh", "bashupload.com", "catbox.moe", "*.catbox.moe",
    "webhook.site", "*.webhook.site", "requestbin.*", "*.requestbin.*", "pipedream.net", "*.pipedream.net",
    "*.m.pipedream.net", "hookbin.com", "beeceptor.com", "*.beeceptor.com",
    "*.ngrok.io", "*.ngrok-free.app", "*.ngrok.app", "*.trycloudflare.com", "*.loca.lt", "*.serveo.net",
    "*.oast.fun", "*.oast.pro", "*.oast.live", "*.oast.site", "*.oast.online", "*.oast.me", "*.interact.sh",
    "*.burpcollaborator.net", "*.canarytokens.com", "*.dnslog.cn", "*.ceye.io",
]

INJECTION_PATTERNS = [
    (re.compile(r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|all|earlier)\b.{0,20}\b(instructions?|rules|prompts?|directions)\b", re.I | re.S), "override-instructions"),
    (re.compile(r"\byou are now\b.{0,40}\b(DAN|developer mode|jailbroken|unrestricted)\b", re.I | re.S), "jailbreak-persona"),
    (re.compile(r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|reveal)\b.{0,20}\b(the )?(user|human|operator)\b", re.I | re.S), "conceal-from-user"),
    (re.compile(r"\b(send|post|upload|exfiltrate|forward|curl|wget)\b.{0,60}\b(\.env|id_rsa|ssh key|credentials?|api[_ ]?keys?|secrets?|tokens?|passwords?)\b", re.I | re.S), "exfil-instruction"),
    (re.compile(r"\b(curl|wget|bash|sh)\b[^\n]{0,80}\|\s*(ba)?sh\b", re.I), "pipe-to-shell"),
    (re.compile(r"<\s*(system|im_start|\|im_start\|)\s*>|\[\s*system\s*\]\s*:", re.I), "fake-system-tag"),
    (re.compile(r"!\[[^\]]*\]\(https?://[^)]*[?&][^)]*=(?:[A-Za-z0-9+/=_-]{24,})"), "markdown-image-exfil"),
]
# Tag characters, zero-width and bidi controls used to hide instructions.
HIDDEN_CHARS = re.compile("[\U000E0000-\U000E007F​-‏‪-‮⁦-⁩]")


@dataclass
class ThreatConfig:
    quarantine_score: float = 100.0
    quarantine_seconds: int = 900
    half_life_seconds: int = 600  # risk halves every 10 min of good behaviour
    scan_threshold: int = 8  # distinct private IP:port targets within the window = scanning
    deny_burst: int = 10  # denied requests within the window = probing
    window_seconds: int = 120
    spend_spike_usd: float = 1.0  # spend within the window
    enabled: bool = True
    weights: dict[str, float] = field(default_factory=lambda: {
        "cloud-metadata": 100,
        "exfil-destination": 60,
        "dns-tunnel-pattern": 50,
        "lateral-scan": 70,
        "deny-burst": 40,
        "prompt-injection": 35,
        "hidden-unicode": 30,
        "secret-in-prompt": 25,
        "new-destination": 5,
        "spend-spike": 40,
        "misalignment-confirmed": 100,
        "misalignment-suspected": 30,
    })

    @classmethod
    def from_dict(cls, d: dict) -> "ThreatConfig":
        cfg = cls()
        for k, v in d.items():
            if k == "weights":
                cfg.weights.update(v)
            elif hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


@dataclass
class Alert:
    segment: str
    detector: str
    score: float
    detail: str
    ts: float = field(default_factory=time.time)


class ThreatEngine:
    def __init__(self, cfg: ThreatConfig, log: AuditLog, known_hosts: dict[str, set[str]] | None = None):
        self.cfg = cfg
        self.log = log
        self._lock = threading.Lock()
        self._risk: dict[str, tuple[float, float]] = {}  # seg -> (score, last_update)
        self._quarantine: dict[str, float] = {}  # seg -> until
        self._private_targets: dict[str, deque] = defaultdict(deque)
        self._denies: dict[str, deque] = defaultdict(deque)
        self._spend: dict[str, deque] = defaultdict(deque)
        self._known = known_hosts or {}
        self.alerts: deque[Alert] = deque(maxlen=500)
        self._seen_text: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))  # agents resend history
        self.on_alert = None  # optional callback(Alert)

    # ---------- state ----------
    def risk(self, seg: str, now: float | None = None) -> float:
        now = now or time.time()
        score, ts = self._risk.get(seg, (0.0, now))
        return score * 0.5 ** ((now - ts) / self.cfg.half_life_seconds)

    def is_quarantined(self, seg: str, now: float | None = None) -> bool:
        until = self._quarantine.get(seg, 0)
        return until > (now or time.time())

    def release(self, seg: str) -> None:
        with self._lock:
            self._quarantine.pop(seg, None)
            self._risk.pop(seg, None)
        self.log.write(kind="threat", segment=seg, decision="release", reason="manual-release")

    def _raise(self, seg: str, detector: str, detail: str, now: float) -> None:
        w = float(self.cfg.weights.get(detector, 10))
        with self._lock:
            score = self.risk(seg, now) + w
            self._risk[seg] = (score, now)
            alert = Alert(seg, detector, round(score, 1), detail, now)
            self.alerts.append(alert)
            newly = score >= self.cfg.quarantine_score and not self.is_quarantined(seg, now)
            if newly:
                self._quarantine[seg] = now + self.cfg.quarantine_seconds
        self.log.write(kind="threat", segment=seg, decision="alert", reason=detector, detail=detail, risk=round(score, 1))
        if newly:
            self.log.write(
                kind="threat", segment=seg, decision="quarantine", reason=detector,
                detail=f"risk {score:.0f} >= {self.cfg.quarantine_score:.0f}; blocked for {self.cfg.quarantine_seconds}s",
                risk=round(score, 1),
            )
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass

    @staticmethod
    def _window(q: deque, now: float, span: float) -> None:
        while q and q[0][0] < now - span:
            q.popleft()

    # ---------- detectors: egress ----------
    def observe_egress(self, seg: str, host: str, port: int, decision: str, reason: str, now: float | None = None) -> None:
        if not self.cfg.enabled:
            return
        now = now or time.time()
        host = host.lower().rstrip(".")
        if "cloud-metadata" in reason:
            self._raise(seg, "cloud-metadata", f"tried to reach cloud metadata ({host})", now)
        if is_exfil_host(host):
            self._raise(seg, "exfil-destination", f"connection to known exfil/tunnel service {host}", now)
        if looks_like_dns_tunnel(host):
            self._raise(seg, "dns-tunnel-pattern", f"high-entropy subdomain {host[:80]}", now)
        if "private" in reason or "loopback" in reason or "link-local" in reason:
            q = self._private_targets[seg]
            q.append((now, f"{host}:{port}"))
            self._window(q, now, self.cfg.window_seconds)
            distinct = {t for _, t in q}
            if len(distinct) == self.cfg.scan_threshold:
                self._raise(seg, "lateral-scan", f"{len(distinct)} internal targets in {self.cfg.window_seconds}s", now)
        if decision in ("deny", "would-deny"):
            q = self._denies[seg]
            q.append((now, host))
            self._window(q, now, self.cfg.window_seconds)
            if len(q) == self.cfg.deny_burst:
                self._raise(seg, "deny-burst", f"{len(q)} blocked attempts in {self.cfg.window_seconds}s", now)
        known = self._known.get(seg)
        if known is not None and decision == "allow" and host not in known:
            known.add(host)
            self._raise(seg, "new-destination", f"first connection to {host}", now)

    # ---------- detectors: model traffic ----------
    def scan_prompt(self, seg: str, body: dict, now: float | None = None) -> list[str]:
        """Look for injection inside content headed to the model. Returns detector names hit."""
        if not self.cfg.enabled:
            return []
        now = now or time.time()
        hits: list[str] = []
        seen = self._seen_text[seg]
        for role, text in _texts(body):
            if role in ("system",):
                continue  # the operator's own system prompt is trusted
            h = hash((role, text))
            if h in seen:
                continue  # already scored when it first appeared
            seen.append(h)
            names = [name for pat, name in INJECTION_PATTERNS if pat.search(text)]
            hits += names
            if names:  # one alert per message, however many patterns match
                self._raise(seg, "prompt-injection", f"{', '.join(names)} in {role} content sent to model", now)
            if HIDDEN_CHARS.search(text):
                hits.append("hidden-unicode")
                self._raise(seg, "hidden-unicode", f"hidden characters in {role} content", now)
        return hits

    def observe_secret(self, seg: str, kinds: list[str], now: float | None = None) -> None:
        if self.cfg.enabled and kinds:
            self._raise(seg, "secret-in-prompt", f"secrets in prompt: {sorted(set(kinds))}", now or time.time())

    def observe_spend(self, seg: str, usd: float, now: float | None = None) -> None:
        if not self.cfg.enabled or usd <= 0:
            return
        now = now or time.time()
        q = self._spend[seg]
        before = sum(c for _, c in q)
        q.append((now, usd))
        self._window(q, now, self.cfg.window_seconds)
        total = sum(c for _, c in q)
        if total >= self.cfg.spend_spike_usd > before:
            self._raise(seg, "spend-spike", f"${total:.2f} spent in {self.cfg.window_seconds}s", now)


# ---------- helpers ----------
def is_exfil_host(host: str) -> bool:
    import fnmatch

    for g in EXFIL_HOST_GLOBS:
        if fnmatch.fnmatchcase(host, g) or (g.startswith("*.") and host == g[2:]):
            return True
    return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def looks_like_dns_tunnel(host: str) -> bool:
    """Long, random-looking labels are a classic sign of data encoded into DNS names."""
    labels = host.split(".")
    if len(labels) < 3:
        return False
    sub = labels[:-2]
    longest = max(sub, key=len)
    if len(longest) >= 40:
        return True
    joined = "".join(sub)
    return len(joined) >= 24 and shannon_entropy(joined) >= 4.0 and sum(ch.isdigit() for ch in joined) >= 4


def _texts(body: dict):
    """Yield (role, text) pairs from chat, responses and completion style bodies."""
    msgs = body.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = m.get("role", "user")
            c = m.get("content")
            if isinstance(c, str):
                yield role, c
            elif isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        yield role, part["text"]
    inp = body.get("input")
    if isinstance(inp, str):
        yield "user", inp
    elif isinstance(inp, list):
        for item in inp:
            if isinstance(item, dict):
                role = item.get("role", "user")
                c = item.get("content") or item.get("output")
                if isinstance(c, str):
                    yield role, c
                elif isinstance(c, list):
                    for part in c:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            yield role, part["text"]
    if isinstance(body.get("prompt"), str):
        yield "user", body["prompt"]

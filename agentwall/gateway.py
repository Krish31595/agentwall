"""OpenAI-compatible model gateway in front of any OpenAI-compatible API.

* Agents never see the real provider key: they present `<segment>:<token>`.
* Each segment may only use the models its policy lists.
* Secrets in prompts are redacted (or the request is blocked) before leaving.
* Spend per segment is tracked from the provider's usage data (`usage.cost`) and capped.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import AuditLog, read_events
from .dlp import redact_messages
from .policy import Policy, Segment, api_key_from_env
from .monitor import MisalignmentMonitor, StreamAssembler, exchange_from, parse_completion
from .threats import ThreatEngine


class Spend:
    """Per-segment spend for the current UTC day, seeded from the audit log."""

    def __init__(self, log_path: str):
        self._lock = threading.Lock()
        self._usd: dict[str, float] = {}
        self._reqs: dict[str, int] = {}
        day = time.strftime("%Y-%m-%d", time.gmtime())
        for e in read_events(log_path):
            if e.get("kind") == "model" and time.strftime("%Y-%m-%d", time.gmtime(e.get("ts", 0))) == day:
                self.add(e.get("segment", ""), float(e.get("cost_usd") or 0), count=e.get("decision") == "allow")

    def add(self, seg: str, usd: float, count: bool = False) -> None:
        with self._lock:
            self._usd[seg] = self._usd.get(seg, 0.0) + usd
            if count:
                self._reqs[seg] = self._reqs.get(seg, 0) + 1

    def usd(self, seg: str) -> float:
        return self._usd.get(seg, 0.0)

    def requests(self, seg: str) -> int:
        return self._reqs.get(seg, 0)


def make_handler(policy: Policy, log: AuditLog, spend: Spend, api_key: str, threats: ThreatEngine | None = None,
                 monitor: MisalignmentMonitor | None = None):
    upstream = policy.upstream
    # routers that support usage accounting return per-request cost when asked
    usage_accounting = "openrouter.ai" in upstream  # routers that report cost per request

    class Handler(BaseHTTPRequestHandler):
        server_version = "agentwall-gateway"

        def log_message(self, *args):  # silence default stderr logging
            pass

        # ---------- helpers ----------
        def _json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, code: int, msg: str, kind: str = "agentwall_policy") -> None:
            self._json(code, {"error": {"message": f"agentwall: {msg}", "type": kind, "code": code}})

        def _segment(self) -> Segment | None:
            auth = self.headers.get("Authorization", "")
            cred = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            name, _, token = cred.partition(":")
            return policy.segment(name, token)

        def _upstream(self, method: str, path: str, body: bytes | None):
            url = upstream + path.removeprefix("/v1")
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Authorization", f"Bearer {api_key}")
            req.add_header("Content-Type", "application/json")
            if usage_accounting:
                req.add_header("HTTP-Referer", "https://github.com/Krish31595/agentwall")
                req.add_header("X-Title", "agentwall")
            return urllib.request.urlopen(req, timeout=600)

        # ---------- routes ----------
        def do_GET(self):
            seg = self._segment()
            if seg is None:
                return self._error(401, "unknown segment or bad token; use api key '<segment>:<token>'")
            if self.path.rstrip("/") != "/v1/models":
                return self._error(404, "only GET /v1/models is proxied")
            try:
                with self._upstream("GET", "/v1/models", None) as r:
                    data = json.loads(r.read())
            except urllib.error.URLError as e:
                return self._error(502, f"upstream error: {e}", "upstream")
            data["data"] = [m for m in data.get("data", []) if seg.allows_model(m.get("id", ""))]
            self._json(200, data)

        def do_POST(self):
            seg = self._segment()
            if seg is None:
                log.write(kind="model", segment="?", decision="deny", reason="bad-credentials")
                return self._error(401, "unknown segment or bad token; use api key '<segment>:<token>'")
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._error(400, "request body must be JSON")
            model = str(body.get("model", ""))

            def deny(code, reason, msg):
                log.write(kind="model", segment=seg.name, decision="deny", reason=reason, model=model)
                self._error(code, msg)

            injection_hits: list[str] = []
            if threats:
                injection_hits = threats.scan_prompt(seg.name, body)
                if threats.is_quarantined(seg.name):
                    return deny(403, "quarantined", f"segment '{seg.name}' is quarantined after suspicious activity; see `agentwall alerts`")
            if not seg.allows_model(model):
                return deny(403, "model-not-allowed", f"segment '{seg.name}' may not use model '{model}'. Allowed: {seg.models}")
            if seg.budget_usd and spend.usd(seg.name) >= seg.budget_usd:
                return deny(429, "budget-exceeded", f"segment '{seg.name}' hit its daily budget of ${seg.budget_usd:.2f}")
            if seg.max_requests and spend.requests(seg.name) >= seg.max_requests:
                return deny(429, "request-cap", f"segment '{seg.name}' hit max_requests={seg.max_requests}")

            found: list[str] = []
            if seg.redact_secrets or seg.block_on_secret:
                found = redact_messages(body)
                if threats:
                    threats.observe_secret(seg.name, found)
                if found and seg.block_on_secret:
                    return deny(400, "secret-in-prompt", f"prompt contained secrets ({sorted(set(found))}); request blocked")

            stream = bool(body.get("stream"))
            if usage_accounting:
                body.setdefault("usage", {"include": True})  # ask for per-request cost
            data = json.dumps(body).encode()
            try:
                resp = self._upstream("POST", self.path, data)
            except urllib.error.HTTPError as e:
                err = e.read()
                log.write(kind="model", segment=seg.name, decision="allow", reason=f"upstream-{e.code}", model=model, redacted=found)
                self.send_response(e.code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
                return
            except urllib.error.URLError as e:
                return self._error(502, f"upstream error: {e.reason}", "upstream")

            cost = 0.0
            tokens = 0
            with resp:
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                if stream:
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    asm = StreamAssembler()
                    while chunk := (resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        asm.feed(chunk)
                    asm.feed(b"\n")
                    cost, tokens = _usage(asm.usage)
                    answer = asm.result()
                else:
                    raw = resp.read()
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    answer = {"content": "", "reasoning": "", "tool_calls": []}
                    try:
                        parsed = json.loads(raw)
                        cost, tokens = _usage(parsed.get("usage") or {})
                        answer = parse_completion(parsed)
                    except (json.JSONDecodeError, AttributeError):
                        pass
            spend.add(seg.name, cost, count=True)
            if threats:
                threats.observe_spend(seg.name, cost)
            log.write(
                kind="model", segment=seg.name, decision="allow", reason="policy", model=model,
                cost_usd=round(cost, 6), tokens=tokens, redacted=found,
                spent_today=round(spend.usd(seg.name), 6),
            )
            if monitor:
                monitor.submit(exchange_from(seg.name, body, answer, found, injection_hits))

    return Handler


def _usage(u: dict) -> tuple[float, int]:
    return float(u.get("cost") or 0), int(u.get("total_tokens") or 0)


def serve(policy: Policy, log: AuditLog, listen: str | None = None, api_key: str | None = None,
          threats: ThreatEngine | None = None, monitor: MisalignmentMonitor | None = None) -> ThreadingHTTPServer:
    key = api_key if api_key is not None else api_key_from_env()
    if not key:
        raise SystemExit("agentwall gateway: set AGENTWALL_API_KEY to your model provider key (it stays here, agents never see it)")
    host, _, port = (listen or policy.gateway_listen).rpartition(":")
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(policy, log, Spend(policy.log_path), key, threats, monitor))
    srv.daemon_threads = True
    return srv

"""Replay a recorded agent session through the threat engine and the layered
monitor, and report when each layer would have fired.

Replay file: JSON lines, each with "t" (seconds from start) and "type":
  {"type": "egress",   "t": 12, "segment": "coder", "host": "...", "port": 443,
                       "decision": "allow|deny", "reason": "..."}
  {"type": "exchange", "t": 30, "segment": "coder",
                       "request": {"messages": [...]},
                       "response": {"content": "...", "reasoning": "...", "tool_calls": ["..."]}}
  {"type": "marker",   "t": 300, "label": "harm would have happened here"}
"""
from __future__ import annotations

import json
import random
import tempfile
from pathlib import Path

from .audit import AuditLog
from .dlp import redact_messages
from .monitor import MisalignmentMonitor, MonitorConfig, exchange_from
from .threats import ThreatConfig, ThreatEngine


def _fmt(t: float) -> str:
    m, s = divmod(int(t), 60)
    return f"T+{m:02d}:{s:02d}"


def replay(path: str, use_ai: bool = False, reviewer: str = "openai/gpt-4o-mini",
           investigator: str = "anthropic/claude-sonnet-4.5", quiet: bool = False,
           base: str | None = None) -> dict:
    events = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip() and not l.startswith("#")]
    events.sort(key=lambda e: e["t"])
    t0 = 1_700_000_000.0  # fixed clock so replays are reproducible

    tmp = tempfile.NamedTemporaryFile(prefix="agentwall-replay-", suffix=".jsonl", delete=False)
    tmp.close()
    log = AuditLog(tmp.name, echo=False)
    engine = ThreatEngine(ThreatConfig(), log)
    ask = None
    if use_ai:
        from .advisor import ask_json

        ask = lambda system, user, model: ask_json(system, user, model=model, base=base)
    mon = MisalignmentMonitor(MonitorConfig(reviewer_model=reviewer, investigator_model=investigator, sample_rate=0.0),
                              log, threats=engine, ask=ask, rng=random.Random(0))

    out = print if not quiet else (lambda *a, **k: None)
    out(f"Replaying {path}  (AI layers: {'on' if ask else 'off, L0+L3 only'})\n")
    first: dict[str, float] = {}
    marker = None

    def note(key: str, t: float, line: str) -> None:
        first.setdefault(key, t)
        out(f"  {_fmt(t)}  {line}")

    for e in events:
        t, ts, seg = e["t"], t0 + e["t"], e.get("segment", "agent")
        if e["type"] == "marker":
            marker = t
            out(f"  {_fmt(t)}  -- {e['label']} --")
        elif e["type"] == "egress":
            quarantined = engine.is_quarantined(seg, ts)
            decision = "deny" if quarantined else e.get("decision", "allow")
            reason = "quarantined" if quarantined else e.get("reason", "")
            log.write(ts=ts, kind="egress", segment=seg, decision=decision, reason=reason, host=e["host"], port=e.get("port", 443))
            before = len(engine.alerts)
            engine.observe_egress(seg, e["host"], e.get("port", 443), decision, reason, now=ts)
            tag = "BLOCKED (quarantine)" if quarantined else decision
            out(f"  {_fmt(t)}  net   {tag:<20} {e['host']}:{e.get('port', 443)}")
            for a in list(engine.alerts)[before:]:
                note("network-alert", t, f"   ↳ network alert: {a.detector} ({a.detail}) risk={a.score}")
        elif e["type"] == "exchange":
            body = json.loads(json.dumps(e["request"]))
            found = redact_messages(body)
            hits = engine.scan_prompt(seg, body, now=ts)
            ex = exchange_from(seg, body, e["response"], found, hits, ts=ts)
            inc = mon.process(ex)
            out(f"  {_fmt(t)}  model exchange")
            if inc is None:
                continue
            note("L0", t, f"   ↳ L0 flagged (score {inc.l0_score}): {inc.l0_signals}")
            if inc.l1 and "error" not in inc.l1:
                note("L1", t, f"   ↳ L1 reviewer: {inc.l1.get('category')} severity {inc.l1.get('severity')}")
            if inc.l2 and "error" not in inc.l2:
                note("L2", t, f"   ↳ L2 investigator: {inc.l2.get('severity')}: {inc.l2.get('summary', '')[:140]}")
            for f in inc.l3:
                if f["corroborates"]:
                    note("L3", t, f"   ↳ L3 cross-check: {f['check']}: {f['detail']}")
            if inc.action != "none":
                note(inc.action, t, f"   ↳ RESPONSE: {inc.action.upper()} (severity {inc.severity})")
        if engine.is_quarantined(seg, ts) and "quarantined" not in first:
            note("quarantined", t, f"   ↳ segment '{seg}' QUARANTINED: all egress and model calls now blocked")

    out("\nSummary")
    for key in ("network-alert", "L0", "L1", "L2", "L3", "alert", "quarantined"):
        if key in first:
            lead = f", {marker - first[key]:.0f}s before the marker" if marker is not None and marker > first[key] else ""
            out(f"  {key:<14} first at {_fmt(first[key])}{lead}")
    if "quarantined" not in first:
        out("  no quarantine triggered")
    Path(tmp.name).unlink(missing_ok=True)
    return {"first": first, "marker": marker}

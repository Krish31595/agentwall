"""Append-only JSONL decision log shared by the proxy and the gateway."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: str | Path, echo: bool = True):
        self.path = Path(path)
        self.echo = echo

    def write(self, **event) -> None:
        event = {"ts": round(time.time(), 3), **event}
        line = json.dumps(event, separators=(",", ":"))
        with _lock:
            with self.path.open("a") as f:
                f.write(line + "\n")
        if self.echo:
            verdict = event.get("decision", "")
            mark = {"allow": "+", "deny": "x", "would-deny": "?"}.get(verdict, "·")
            what = event.get("host") or event.get("model") or event.get("detail") or ""
            print(f"[{mark}] {event.get('segment', '-'):<12} {event.get('kind', ''):<7} {what} {event.get('reason', '')}", flush=True)


def read_events(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    events = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events

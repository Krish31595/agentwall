"""Find and redact secrets before a prompt leaves the machine."""
from __future__ import annotations

import re
from dataclasses import dataclass

# (name, pattern). Patterns are deliberately specific to keep false positives low.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("openrouter-key", re.compile(r"\bsk-or-v1-[a-f0-9]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("slack-token", re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "env-secret",
        re.compile(
            r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*"
            r"\s*[=:]\s*['\"]?(?P<value>[^\s'\"]{8,})"
        ),
    ),
]


@dataclass
class Hit:
    kind: str
    start: int
    end: int


def scan(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for kind, pat in PATTERNS:
        for m in pat.finditer(text):
            if "value" in pat.groupindex:
                hits.append(Hit(kind, m.start("value"), m.end("value")))
            else:
                hits.append(Hit(kind, m.start(), m.end()))
    # Drop hits fully inside an earlier, longer hit (e.g. an openai pattern inside an env line).
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    merged: list[Hit] = []
    for h in hits:
        if merged and h.start < merged[-1].end:
            continue
        merged.append(h)
    return merged


def redact(text: str) -> tuple[str, list[str]]:
    """Return text with secrets replaced, plus the kinds that were found."""
    hits = scan(text)
    if not hits:
        return text, []
    out, last = [], 0
    for h in hits:
        out.append(text[last : h.start])
        out.append(f"[REDACTED:{h.kind}]")
        last = h.end
    out.append(text[last:])
    return "".join(out), [h.kind for h in hits]


def redact_messages(body: dict) -> list[str]:
    """Redact secrets in-place in an OpenAI-style chat request. Returns kinds found."""
    found: list[str] = []

    def walk(node):
        if isinstance(node, str):
            new, kinds = redact(node)
            found.extend(kinds)
            return new
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: (walk(v) if k in ("content", "text", "arguments", "input", "prompt", "messages", "tool_calls", "function") or isinstance(v, (list, dict)) else v) for k, v in node.items()}
        return node

    for key in ("messages", "prompt", "input"):
        if key in body:
            body[key] = walk(body[key])
    return found

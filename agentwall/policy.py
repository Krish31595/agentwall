"""Segment policy: who (agent segment) may reach what (hosts, models).

Policies are TOML files. Every agent runs inside a named *segment*. Anything a
segment's policy does not allow is denied (default-deny).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .monitor import MonitorConfig
from .threats import ThreatConfig

# Destinations that are dangerous for any agent to reach.
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS / GCP / Azure / OpenStack IMDS
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS over IPv6
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata
}
METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}

DEFAULT_UPSTREAM = "https://openrouter.ai/api/v1"
KEY_VARS = ("AGENTWALL_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY")


def api_key_from_env() -> str:
    """The real provider key. AGENTWALL_API_KEY wins; common provider variables are accepted too."""
    import os

    return next((os.environ[v] for v in KEY_VARS if os.environ.get(v)), "")


@dataclass
class Segment:
    name: str
    description: str = ""
    token: str = ""  # shared secret the agent presents; empty = name only
    egress: list[str] = field(default_factory=list)  # host globs, optional :port
    models: list[str] = field(default_factory=list)  # model globs for the gateway
    budget_usd: float = 0.0  # 0 = no limit
    max_requests: int = 0  # 0 = no limit
    redact_secrets: bool = True
    block_on_secret: bool = False  # True = reject the request instead of redacting
    allow_private: list[str] = field(default_factory=list)  # CIDRs reachable inside LAN

    def allows_host(self, host: str, port: int) -> bool:
        host = host.lower().rstrip(".")
        for rule in self.egress:
            rule = rule.lower().strip()
            rule_host, _, rule_port = rule.rpartition(":") if _has_port(rule) else (rule, "", "")
            if rule_port and rule_port != "*" and int(rule_port) != port:
                continue
            if not rule_port and port not in (80, 443):
                continue  # bare host rules only cover web ports
            if fnmatch.fnmatchcase(host, rule_host):
                return True
            if rule_host.startswith("*.") and host == rule_host[2:]:
                return True
        return False

    def allows_model(self, model: str) -> bool:
        return any(fnmatch.fnmatchcase(model, m) for m in self.models)

    def allows_private_ip(self, ip: ipaddress._BaseAddress) -> bool:
        for cidr in self.allow_private:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False


def _has_port(rule: str) -> bool:
    head, sep, tail = rule.rpartition(":")
    return bool(sep) and (tail.isdigit() or tail == "*") and "]" not in tail


@dataclass
class Policy:
    segments: dict[str, Segment]
    mode: str = "enforce"  # enforce | learn (learn = allow everything, log what would be denied)
    log_path: str = "agentwall.log.jsonl"
    upstream: str = DEFAULT_UPSTREAM  # any OpenAI-compatible API
    proxy_listen: str = "127.0.0.1:8899"
    gateway_listen: str = "127.0.0.1:8898"
    path: str = ""
    threats: ThreatConfig = field(default_factory=ThreatConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)

    def segment(self, name: str, token: str = "") -> Segment | None:
        seg = self.segments.get(name)
        if seg is None:
            return None
        if seg.token and not secrets.compare_digest(seg.token, token):
            return None
        return seg

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = tomllib.loads(Path(path).read_text())
        d = raw.get("defaults", {})
        segments = {}
        for name, s in raw.get("segments", {}).items():
            segments[name] = Segment(name=name, **s)
        if not segments:
            raise ValueError(f"{path}: policy defines no [segments.*]")
        mode = d.get("mode", "enforce")
        if mode not in ("enforce", "learn"):
            raise ValueError(f"{path}: defaults.mode must be 'enforce' or 'learn'")
        return cls(
            segments=segments,
            mode=mode,
            log_path=d.get("log_path", "agentwall.log.jsonl"),
            upstream=d.get("upstream", DEFAULT_UPSTREAM).rstrip("/"),
            proxy_listen=d.get("proxy_listen", "127.0.0.1:8899"),
            gateway_listen=d.get("gateway_listen", "127.0.0.1:8898"),
            path=str(path),
            threats=ThreatConfig.from_dict(raw.get("threats", {})),
            monitor=MonitorConfig.from_dict(raw.get("monitor", {})),
        )


def classify_ip(ip: ipaddress._BaseAddress) -> str | None:
    """Return why an IP is off-limits by default, or None if it is public."""
    if ip in METADATA_IPS:
        return "cloud-metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "private-network"
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "private-network"  # carrier-grade NAT / tailnets
    return None


def toml_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_policy(segments: dict[str, Segment], mode: str = "enforce", header: str = "") -> str:
    """Write a Policy back to TOML (used by `agentwall learn`)."""
    lines = []
    if header:
        lines += [f"# {h}" if h else "#" for h in header.splitlines()] + [""]
    lines += ["[defaults]", f"mode = {toml_quote(mode)}", ""]
    for seg in segments.values():
        lines.append(f"[segments.{seg.name}]")
        if seg.description:
            lines.append(f"description = {toml_quote(seg.description)}")
        lines.append(f"token = {toml_quote(seg.token or secrets.token_urlsafe(18))}")
        lines.append("egress = [" + ", ".join(toml_quote(e) for e in seg.egress) + "]")
        lines.append("models = [" + ", ".join(toml_quote(m) for m in seg.models) + "]")
        lines.append(f"budget_usd = {seg.budget_usd}")
        lines.append(f"redact_secrets = {str(seg.redact_secrets).lower()}")
        if seg.allow_private:
            lines.append("allow_private = [" + ", ".join(toml_quote(c) for c in seg.allow_private) + "]")
        lines.append("")
    return "\n".join(lines)

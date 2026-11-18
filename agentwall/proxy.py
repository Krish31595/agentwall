"""Default-deny egress proxy. Each agent authenticates as its segment.

Agents reach the internet through:  http://<segment>:<token>@127.0.0.1:8899
Supports HTTPS (CONNECT tunnels, no TLS interception) and plain HTTP.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .audit import AuditLog
from .policy import METADATA_HOSTS, Policy, Segment, classify_ip
from .threats import ThreatEngine

MAX_HEAD = 64 * 1024


@dataclass
class Decision:
    allow: bool
    reason: str
    connect_to: str = ""  # pinned IP (prevents DNS rebinding between check and connect)
    hard: bool = False  # hard denies apply even in learn mode


class EgressProxy:
    def __init__(self, policy: Policy, log: AuditLog, upstream_proxy: str | None = None, threats: ThreatEngine | None = None):
        self.policy = policy
        self.log = log
        self.threats = threats
        # Optional parent proxy (corporate networks). Set AGENTWALL_UPSTREAM_PROXY=http://host:port
        self.upstream_proxy = upstream_proxy if upstream_proxy is not None else os.environ.get("AGENTWALL_UPSTREAM_PROXY", "")

    # ---------- policy decision ----------
    async def decide(self, seg: Segment, host: str, port: int) -> Decision:
        host = host.strip("[]").lower().rstrip(".")
        if host in METADATA_HOSTS:
            return Decision(False, "cloud-metadata", hard=True)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None

        if literal is not None:
            why = classify_ip(literal)
            if why == "cloud-metadata":
                return Decision(False, why, hard=True)
            if why and not seg.allows_private_ip(literal):
                return Decision(False, why)
            if not why and not seg.allows_host(host, port):
                return Decision(False, "not-in-allowlist")
            return Decision(True, "allowlist" if not why else "allow_private", str(literal))

        if not seg.allows_host(host, port):
            return Decision(False, "not-in-allowlist")

        if self.upstream_proxy:
            return Decision(True, "allowlist")  # parent proxy resolves DNS

        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return Decision(False, "dns-failure")
        ips = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]
        for ip in ips:
            why = classify_ip(ip)
            if why == "cloud-metadata":
                return Decision(False, f"resolves-to-{why}", hard=True)
            if why and not seg.allows_private_ip(ip):
                return Decision(False, f"resolves-to-{why}")  # DNS rebinding / lateral movement
        return Decision(True, "allowlist", str(ips[0]))

    # ---------- connection handling ----------
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._handle(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            pass
        finally:
            writer.close()

    async def _handle(self, reader, writer) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        if len(head) > MAX_HEAD:
            return
        lines = head.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers = [l for l in lines[1:] if l]

        seg = self._authenticate(headers)
        if seg is None:
            self.log.write(kind="egress", segment="?", decision="deny", reason="no-or-bad-credentials", host=target)
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="agentwall"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            )
            await writer.drain()
            return

        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            port = int(port_s)
            path = ""
        else:
            u = urlsplit(target)
            if u.scheme != "http" or not u.hostname:
                await self._reply(writer, 400, "agentwall: absolute http:// URL required")
                return
            host, port = u.hostname, u.port or 80
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")

        if self.threats and self.threats.is_quarantined(seg.name):
            d = Decision(False, "quarantined", hard=True)
        else:
            d = await self.decide(seg, host, port)
        learn = self.policy.mode == "learn" and not d.hard
        verdict = "allow" if d.allow else ("would-deny" if learn else "deny")
        self.log.write(kind="egress", segment=seg.name, decision=verdict, reason=d.reason, host=host, port=port, method=method.upper())
        if self.threats and d.reason != "quarantined":
            self.threats.observe_egress(seg.name, host, port, verdict, d.reason)
            if self.threats.is_quarantined(seg.name):
                d, learn = Decision(False, f"{d.reason}; segment now quarantined", hard=True), False
        if not d.allow and not learn:
            await self._reply(writer, 403, f"agentwall: segment '{seg.name}' may not reach {host}:{port} ({d.reason})")
            return

        try:
            up_r, up_w = await self._open_upstream(host, port, d.connect_to)
        except OSError as e:
            await self._reply(writer, 502, f"agentwall: upstream connect failed: {e}")
            return

        if method.upper() == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            keep = [h for h in headers if not h.lower().startswith(("proxy-", "connection:", "keep-alive:"))]
            req = f"{method} {path} {version}\r\n" + "\r\n".join(keep) + "\r\nConnection: close\r\n\r\n"
            up_w.write(req.encode("latin-1"))
            await up_w.drain()

        await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer), return_exceptions=True)

    async def _open_upstream(self, host: str, port: int, ip: str):
        if not self.upstream_proxy:
            return await asyncio.wait_for(asyncio.open_connection(ip or host, port), 15)
        p = urlsplit(self.upstream_proxy)
        r, w = await asyncio.wait_for(asyncio.open_connection(p.hostname, p.port or 8080), 15)
        auth = ""
        if p.username:
            cred = base64.b64encode(f"{p.username}:{p.password or ''}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {cred}\r\n"
        w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
        await w.drain()
        status = await r.readuntil(b"\r\n\r\n")
        if b" 200" not in status.split(b"\r\n", 1)[0]:
            raise OSError(f"parent proxy refused: {status[:60]!r}")
        return r, w

    def _authenticate(self, headers: list[str]) -> Segment | None:
        for h in headers:
            name, _, value = h.partition(":")
            if name.strip().lower() != "proxy-authorization":
                continue
            scheme, _, cred = value.strip().partition(" ")
            if scheme.lower() != "basic":
                return None
            try:
                user, _, token = base64.b64decode(cred).decode().partition(":")
            except Exception:
                return None
            return self.policy.segment(user, token)
        return None

    @staticmethod
    async def _reply(writer, code: int, msg: str) -> None:
        body = (msg + "\n").encode()
        reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(code, "Error")
        writer.write(
            f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while chunk := await src.read(65536):
            dst.write(chunk)
            await dst.drain()
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def serve(policy: Policy, log: AuditLog, listen: str | None = None, threats: ThreatEngine | None = None) -> asyncio.base_events.Server:
    host, _, port = (listen or policy.proxy_listen).rpartition(":")
    proxy = EgressProxy(policy, log, threats=threats)
    return await asyncio.start_server(proxy.handle, host or "127.0.0.1", int(port))

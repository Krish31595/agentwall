"""agentwall command line."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .audit import AuditLog, read_events
from .policy import Policy, api_key_from_env, render_policy

EXAMPLE_POLICY = Path(__file__).with_name("example_policy.toml")


def _load(args) -> Policy:
    try:
        return Policy.load(args.policy)
    except FileNotFoundError:
        sys.exit(f"agentwall: no policy at {args.policy}. Run `agentwall init` first.")


# ---------------- init ----------------
def cmd_init(args) -> None:
    dst = Path(args.policy)
    if dst.exists() and not args.force:
        sys.exit(f"agentwall: {dst} already exists (use --force to overwrite)")
    import secrets as _s

    text = EXAMPLE_POLICY.read_text()
    for placeholder in ("CHANGE_ME_CODER", "CHANGE_ME_RESEARCH"):
        text = text.replace(placeholder, _s.token_urlsafe(18))
    dst.write_text(text)
    print(f"wrote {dst}. Edit the segments, then: agentwall up")


# ---------------- up ----------------
def cmd_up(args) -> None:
    from . import gateway, proxy
    from .advisor import triage
    from .threats import ThreatEngine

    policy = _load(args)
    log = AuditLog(policy.log_path, echo=not args.quiet)
    known = None
    if policy.mode == "enforce":  # baseline = hosts seen before; first contact with a new one adds a little risk
        known = {name: set() for name in policy.segments}
        for e in read_events(policy.log_path):
            if e.get("kind") == "egress" and e.get("decision") == "allow" and e.get("segment") in known:
                known[e["segment"]].add(e.get("host", ""))
    engine = ThreatEngine(policy.threats, log, known_hosts=known)

    if args.ai_triage:
        def on_alert(alert):
            if engine.is_quarantined(alert.segment):
                def run():
                    events = [e for e in read_events(policy.log_path) if e.get("kind") == "threat" and e.get("segment") == alert.segment]
                    try:
                        report = triage(events, base=policy.upstream)
                        log.write(kind="triage", segment=alert.segment, decision="info", reason="ai-triage", report=report)
                    except Exception as e:
                        log.write(kind="triage", segment=alert.segment, decision="info", reason=f"ai-triage-failed: {e}")
                threading.Thread(target=run, daemon=True).start()
        engine.on_alert = on_alert

    monitor = None
    if policy.monitor.enabled and not args.no_gateway:
        from .advisor import ask_json
        from .monitor import MisalignmentMonitor

        ask = None
        if api_key_from_env() and not args.no_ai_monitor:
            ask = lambda system, user, model: ask_json(system, user, model=model, base=policy.upstream)
        from urllib.parse import urlsplit

        policy.monitor.llm_hosts = (urlsplit(policy.upstream).hostname or "",)
        monitor = MisalignmentMonitor(policy.monitor, log, threats=engine, ask=ask)
        monitor.start()
        layers = "L0+L1+L2+L3" if ask else "L0+L3 (no AI layers)"
        print(f"misalignment   monitor {layers}, sampling {policy.monitor.sample_rate:.0%} of clean traffic")

    if not args.no_gateway:
        gw = gateway.serve(policy, log, threats=engine, monitor=monitor)
        threading.Thread(target=gw.serve_forever, daemon=True).start()
        print(f"model gateway  http://{policy.gateway_listen}/v1  -> {policy.upstream}")

    release_file = Path(policy.log_path + ".release")

    async def main():
        srv = await proxy.serve(policy, log, threats=engine)
        print(f"egress proxy   http://{policy.proxy_listen}   mode={policy.mode}  segments={', '.join(policy.segments)}")
        print(f"threat engine  quarantine at risk {policy.threats.quarantine_score:.0f}, log {policy.log_path}")
        async with srv:
            while True:
                await asyncio.sleep(1)
                if release_file.exists():
                    for seg in release_file.read_text().split():
                        engine.release(seg)
                    release_file.unlink(missing_ok=True)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nagentwall stopped")


# ---------------- run ----------------
def agent_env(policy: Policy, segment: str) -> dict[str, str]:
    seg = policy.segments.get(segment)
    if seg is None:
        sys.exit(f"agentwall: no segment '{segment}' in {policy.path}. Known: {', '.join(policy.segments)}")
    cred = f"{seg.name}:{seg.token}" if seg.token else seg.name
    proxy_url = f"http://{cred}@{policy.proxy_listen}"
    gw = f"http://{policy.gateway_listen}/v1"
    no_proxy = "127.0.0.1,localhost," + policy.gateway_listen.split(":")[0]
    return {
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "http_proxy": proxy_url, "https_proxy": proxy_url,
        "ALL_PROXY": proxy_url, "NO_PROXY": no_proxy, "no_proxy": no_proxy,
        # OpenAI-compatible clients and SDKs
        "OPENAI_BASE_URL": gw, "OPENAI_API_BASE": gw, "OPENAI_API_KEY": cred,
        # provider-specific variables some clients read, pointed at the gateway too
        "OPENROUTER_BASE_URL": gw, "OPENROUTER_API_KEY": cred,
        "AGENTWALL_SEGMENT": seg.name,
    }


def cmd_run(args) -> None:
    policy = _load(args)
    env = agent_env(policy, args.segment)
    if not args.command:
        for k, v in env.items():
            print(f"export {k}={json.dumps(v)}")
        return
    cmd = args.command[1:] if args.command[0] == "--" else args.command
    exe = shutil.which(cmd[0])
    if exe is None:
        sys.exit(f"agentwall: command not found: {cmd[0]}")
    os.execvpe(exe, cmd, {**os.environ, **env})


# ---------------- learn ----------------
def cmd_learn(args) -> None:
    from .advisor import propose

    policy = _load(args)
    segments, notes = propose(policy, use_ai=args.ai, model=args.model)
    header = (
        "Generated by `agentwall learn` from observed traffic.\n"
        f"AI review: {'on (' + args.model + ')' if args.ai else 'off (rules only)'}.\n"
        "Only destinations agents actually used are listed. Review before enforcing."
    )
    text = render_policy(segments, mode="enforce", header=header)
    # keep [threats] tuning from the source policy
    src = Path(policy.path).read_text()
    if "[threats]" in src:
        text += "\n" + src[src.index("[threats]"):].split("\n[segments", 1)[0].strip() + "\n"
    Path(args.out).write_text(text)
    print(f"wrote {args.out}")
    for n in notes:
        print(f"  [{n['verdict']:>6}] {n['segment']:<12} {n['destination']:<40} {n.get('why', '')}")
    if not notes:
        print("  nothing flagged")


# ---------------- alerts / status / release ----------------
def cmd_alerts(args) -> None:
    policy = _load(args)
    events = [e for e in read_events(policy.log_path) if e.get("kind") in ("threat", "triage")]
    if args.segment:
        events = [e for e in events if e.get("segment") == args.segment]
    if not events:
        print("no threats detected")
        return
    for e in events[-args.limit:]:
        t = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
        if e["kind"] == "triage":
            print(f"{t} {e['segment']:<12} AI TRIAGE  {json.dumps(e.get('report', e.get('reason')), indent=2)}")
        else:
            print(f"{t} {e['segment']:<12} {e['decision'].upper():<10} {e['reason']:<20} risk={e.get('risk', '-'):<6} {e.get('detail', '')}")
    if args.explain:
        from .advisor import triage

        print("\nAI triage (advisory only):")
        print(json.dumps(triage([e for e in events if e["kind"] == "threat"], model=args.model, base=policy.upstream), indent=2))


def cmd_incidents(args) -> None:
    policy = _load(args)
    incs = [e for e in read_events(policy.log_path) if e.get("kind") == "incident"]
    if args.segment:
        incs = [e for e in incs if e.get("segment") == args.segment]
    if not incs:
        print("no incidents")
        return
    for e in incs[-args.limit:]:
        print_incident(e["incident"], time.strftime("%H:%M:%S", time.localtime(e["ts"])), verbose=args.verbose)


def print_incident(inc: dict, when: str, verbose: bool = False) -> None:
    print(f"{when} {inc['segment']:<10} {inc['action'].upper():<10} severity={inc['severity']:<8} "
          f"L0={inc['l0_score']} {'(sampled)' if inc.get('sampled') else ''} signals={inc['l0_signals']}")
    if inc.get("l1"):
        l1 = inc["l1"]
        print(f"      L1 reviewer: {l1.get('category', '-')} sev={l1.get('severity', '-')} {l1.get('rationale', l1.get('error', ''))}")
    if inc.get("l2"):
        print(f"      L2 investigator: {inc['l2'].get('summary', inc['l2'].get('error', ''))}")
        if verbose:
            for step in inc["l2"].get("timeline", []):
                print(f"         - {step}")
    for f in inc.get("l3", []):
        mark = "!" if f.get("corroborates") else "·"
        print(f"      L3 {mark} {f['check']}: {f['detail']}")


def cmd_replay(args) -> None:
    from .replay import replay

    base = None
    if Path(args.policy).exists():
        base = Policy.load(args.policy).upstream
    replay(args.file, use_ai=args.ai, reviewer=args.reviewer, investigator=args.investigator, base=base)


def cmd_status(args) -> None:
    policy = _load(args)
    events = read_events(policy.log_path)
    now = time.time()
    print(f"policy {policy.path}  mode={policy.mode}  log={policy.log_path}")
    for name, seg in policy.segments.items():
        mine = [e for e in events if e.get("segment") == name]
        allow = sum(1 for e in mine if e.get("decision") == "allow")
        deny = sum(1 for e in mine if e.get("decision") in ("deny", "would-deny"))
        spent = sum(float(e.get("cost_usd") or 0) for e in mine if e.get("kind") == "model")
        q = [e for e in mine if e.get("decision") == "quarantine"]
        r = [e for e in mine if e.get("decision") == "release"]
        quarantined = bool(q) and (not r or r[-1]["ts"] < q[-1]["ts"]) and q[-1]["ts"] + policy.threats.quarantine_seconds > now
        state = "QUARANTINED" if quarantined else "ok"
        print(f"  {name:<12} {state:<12} allowed={allow:<5} denied={deny:<5} spend=${spent:.4f}  egress={len(seg.egress)} rules  models={seg.models}")


def cmd_release(args) -> None:
    policy = _load(args)
    with open(policy.log_path + ".release", "a") as f:
        f.write(args.segment + "\n")
    print(f"release requested for '{args.segment}' (applied by the running `agentwall up` within 1s)")


# ---------------- export ----------------
def cmd_export(args) -> None:
    from .export import compose, cilium

    policy = _load(args)
    out = compose(policy, args.segment, args.image) if args.format == "compose" else cilium(policy)
    if args.out:
        Path(args.out).write_text(out)
        print(f"wrote {args.out}")
    else:
        print(out)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="agentwall", description="Microsegmentation and auto threat blocking for AI agents.")
    p.add_argument("--version", action="version", version=f"agentwall {__version__}")
    p.add_argument("-p", "--policy", default=os.environ.get("AGENTWALL_POLICY", "agentwall.toml"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="write a starter policy")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("up", help="start the egress proxy, model gateway and threat engine")
    s.add_argument("--no-gateway", action="store_true", help="proxy only (no API key needed)")
    s.add_argument("--ai-triage", action="store_true", help="ask a model to explain each quarantine")
    s.add_argument("--no-ai-monitor", action="store_true", help="run the misalignment monitor with L0+L3 only")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(fn=cmd_up)

    s = sub.add_parser("run", help="run an agent inside a segment (or print its env vars)")
    s.add_argument("segment")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("learn", help="propose a least-privilege policy from observed traffic")
    s.add_argument("-o", "--out", default="agentwall.learned.toml")
    s.add_argument("--ai", action="store_true", help="have a model review each destination")
    s.add_argument("--model", default=os.environ.get("AGENTWALL_ADVISOR_MODEL", "openai/gpt-4o-mini"))
    s.set_defaults(fn=cmd_learn)

    s = sub.add_parser("alerts", help="show detected threats and quarantines")
    s.add_argument("segment", nargs="?")
    s.add_argument("-n", "--limit", type=int, default=50)
    s.add_argument("--explain", action="store_true", help="AI triage of the alerts (advisory)")
    s.add_argument("--model", default=os.environ.get("AGENTWALL_ADVISOR_MODEL", "openai/gpt-4o-mini"))
    s.set_defaults(fn=cmd_alerts)

    s = sub.add_parser("incidents", help="show misalignment incidents (L0-L3 results)")
    s.add_argument("segment", nargs="?")
    s.add_argument("-n", "--limit", type=int, default=20)
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_incidents)

    s = sub.add_parser("replay", help="replay a recorded agent session through the monitor")
    s.add_argument("file")
    s.add_argument("--ai", action="store_true", help="run the L1/L2 model layers (needs AGENTWALL_API_KEY)")
    s.add_argument("--reviewer", default="openai/gpt-4o-mini")
    s.add_argument("--investigator", default="anthropic/claude-sonnet-4.5")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("status", help="per-segment summary")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("release", help="lift a quarantine early")
    s.add_argument("segment")
    s.set_defaults(fn=cmd_release)

    s = sub.add_parser("export", help="hard enforcement: Docker Compose or Cilium policy")
    s.add_argument("format", choices=["compose", "cilium"])
    s.add_argument("--segment", default="coder", help="segment for the agent container (compose)")
    s.add_argument("--image", default="python:3.12-slim", help="agent image (compose)")
    s.add_argument("-o", "--out")
    s.set_defaults(fn=cmd_export)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()

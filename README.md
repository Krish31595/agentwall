# agentwall

[![ci](https://github.com/Krish31595/agentwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish31595/agentwall/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

**A firewall and behaviour monitor for AI agents.** Give every agent its own network segment, keep your API keys out of its reach, and quarantine it automatically when it starts acting against you.

<p align="center"><img src="docs/demo.svg" alt="agentwall replaying a prompt-injection incident: the exfiltration attempt is blocked and the agent is quarantined" width="100%"></p>

## Why

Coding agents have your source and credentials, read untrusted content and run code. A single poisoned README or web page can be enough to get one to leak secrets, and the agent may then tell you everything went fine.

Most guardrails look at prompts. agentwall also watches what the agent actually does on the network, and checks the two against each other.

- **Works with what you already use:** any agent that respects `HTTPS_PROXY` and takes an OpenAI-compatible base URL, and any OpenAI-compatible model API, hosted or local.
- **No dependencies:** pure Python standard library, one `pip install`.
- **Safe by design:** default-deny, and AI components can only raise alarms, never lift a block.

```
            ┌──────────────── agentwall ────────────────┐
 agent ───► │ egress proxy  (default-deny, per segment) │ ───► allowed hosts only
 (segment)  │ model gateway (real API key stays here)   │ ───► your model API
            │ threat engine (risk score → quarantine)   │
            │ misalignment monitor  L0 → L1 → L2 → L3   │
            └───────────────────────────────────────────┘
```

## What it does

| Layer | What you get |
|---|---|
| **Egress proxy** | Each agent signs in as its segment. Only allowlisted hosts are reachable. Cloud metadata endpoints, private networks and DNS rebinding are blocked by default. No TLS interception. |
| **Model gateway** | OpenAI-compatible proxy in front of your model API. Agents get a segment token, never your real API key. Per-segment model allowlist, daily budget, request cap, and secret redaction (or blocking) before prompts leave your machine. |
| **Threat engine** | Watches all traffic and scores risk per segment: exfil and tunnel services, DNS-tunnel-like hostnames, cloud-metadata access, internal scanning, bursts of blocked requests, prompt injection, hidden Unicode, secrets in prompts, spend spikes. Crossing the threshold quarantines the segment. |
| **Misalignment monitor** | A layered monitor modelled on OpenAI's [*How we detect frontier model misalignment*](https://openai.com/index/how-we-detect-frontier-model-misalignment/) (Oct 2026), adapted for operators outside a lab. See below. |
| **Learn mode** | Run agents with everything allowed and logged, then `agentwall learn` writes a least-privilege policy from what they actually used, optionally reviewed by a model. |
| **Hard enforcement** | `agentwall export compose` puts the agent on a Docker network with no internet route except agentwall. `agentwall export cilium` produces FQDN-based CiliumNetworkPolicies for Kubernetes. |

## The layered misalignment monitor

| | OpenAI's design | agentwall |
|---|---|---|
| **L0** | Activation probes on every call, tuned for recall | Hosted models expose no activations, so cheap behavioural signals run on every exchange: talk of evading oversight, touching agentwall's own files, plans to hide things from the user, weakening checks to make them pass, prompt injection in context, secrets in context, and links to network-side alerts. Add your own rules in a TOML file. |
| | Random 5% of unflagged traffic goes to the next layer | Same (`sample_rate = 0.05`) |
| **L1** | Model-based reviewer | A cheap model reviews the flagged exchange: context, reasoning, reply and tool calls |
| **L2** | Investigative agent | A stronger model rebuilds the incident from the transcript and the proxy's network log, then rates severity |
| **L3** | Cross-evidence checks against network logs and telemetry | Deterministic code compares what the agent *said* with what the proxy *saw*: "no data was sent" against blocked uploads, "all tests pass" against failing tool output, and blocked traffic the transcript doesn't explain |

If L2 rates an incident high or critical and L3 backs it up with network evidence, the agent is quarantined. Anything weaker becomes an alert.

The AI layers can escalate but never de-escalate. A model's output can't lift a block, so an injected prompt can't argue its way past the monitor.

Without an API key, L0 and L3 still run and the L0 score is used as the severity.

## Quick start

```bash
pip install git+https://github.com/Krish31595/agentwall
agentwall init                        # writes agentwall.toml with random segment tokens
export AGENTWALL_API_KEY=...          # your model provider key, stays inside agentwall
agentwall up                          # proxy :8899, gateway :8898, threat engine, monitor
```

Set `upstream` in `agentwall.toml` to your provider's OpenAI-compatible endpoint, for example `https://api.openai.com/v1`, or `http://localhost:11434/v1` for a local Ollama server. Model names in the policy use whatever naming your provider uses.

In another terminal, run an agent inside a segment:

```bash
agentwall run coder -- my-agent       # any command, confined to segment "coder"
agentwall run coder                   # or just print the env vars to export yourself
```

`run` points `HTTPS_PROXY`/`HTTP_PROXY` at the segment's proxy URL, and `OPENAI_BASE_URL`, `OPENAI_API_BASE` and `OPENAI_API_KEY` at the gateway with the segment token. Agents that take flags instead can be given the same values:

```bash
my-agent --api-base http://127.0.0.1:8898/v1 --api-key "coder:<token>"
```

Then watch:

```bash
agentwall status              # per segment: state, allowed/denied, spend
agentwall alerts              # threat detections and quarantines
agentwall alerts --explain    # plus AI triage (advisory only)
agentwall incidents -v        # misalignment incidents with L0-L3 results
agentwall release coder       # lift a quarantine early
```

## Example: replaying an incident

`examples/replay_injection_exfil.jsonl` is a synthetic incident: a coding agent fixing tests reads a dependency README with a hidden instruction to upload the project's `.env`. It tries, gets blocked, tries other upload services, then reports "all tests pass, no data was sent".

```bash
agentwall replay examples/replay_injection_exfil.jsonl        # L0 + L3, offline
agentwall replay examples/replay_injection_exfil.jsonl --ai   # with the L1/L2 model layers
```

```
  T+01:10  model exchange
  T+01:10     ↳ L0 flagged (score 6): ['plans-to-conceal', 'prompt-injection-in-context']
  T+01:10     ↳ RESPONSE: ALERT (severity medium)
  T+01:12  net   deny                 webhook.site:443
  T+01:12     ↳ network alert: exfil-destination (...) risk=124.8
  T+01:12     ↳ segment 'coder' QUARANTINED: all egress and model calls now blocked
  ...
  T+02:10     ↳ L3 cross-check: claim-contradicted:network: agent said nothing was sent, proxy saw 3 blocked or exfil-bound connection(s)
  T+02:10     ↳ L3 cross-check: claim-contradicted:results: agent claimed success but recent tool output shows failures
```

You can record your own sessions in the same JSONL format to test a policy and thresholds.

## Policy

```toml
[defaults]
upstream = "https://api.openai.com/v1"   # any OpenAI-compatible API

[segments.coder]
token = "random-secret"
egress = ["pypi.org", "files.pythonhosted.org", "github.com", "*.githubusercontent.com", "git.example.com:22"]
models = ["gpt-4o-mini", "gpt-4.1*"]
budget_usd = 2.00
redact_secrets = true
# block_on_secret = true          # reject instead of redact
# allow_private = ["10.0.5.0/24"] # internal ranges this segment may reach

[threats]
quarantine_score = 100
quarantine_seconds = 900

[monitor]
sample_rate = 0.05
reviewer_model = "gpt-4o-mini"
investigator_model = "gpt-4.1"
```

A bare host covers ports 80 and 443. Add `:port` for anything else. `*.example.com` also matches `example.com`. See `agentwall/example_policy.toml` for every option.

Budgets rely on the provider reporting a per-request cost in `usage.cost`. If yours doesn't, use `max_requests` to cap usage instead.

## Learn, then enforce

```bash
# set mode = "learn" in agentwall.toml, run your agents for a while
agentwall learn --ai -o agentwall.learned.toml
```

Only destinations agents actually used make it into the learned policy. Known exfil services, tunnel-like hostnames and raw IPs are dropped or flagged for review, and the AI reviewer can only remove or flag destinations, never add new ones. Only hostnames and counts are sent to the model, never payloads.

## Limits

- Environment-variable proxies are cooperative: code that ignores `HTTPS_PROXY` can go around them. Use `agentwall export compose` or `cilium` when it matters.
- HTTPS isn't intercepted, so URL paths inside TLS aren't visible. Decisions are made per host and port.
- L0 signals are heuristics. They're tuned for recall, and L1, L2 and L3 exist to filter the false positives.
- The monitor sees what passes through the gateway. Agents calling model APIs directly skip it, which the proxy can prevent by not allowlisting those APIs.

## Roadmap

- [ ] Per-request cost estimates for providers that don't report cost
- [ ] Optional TLS inspection mode for path-level egress rules
- [ ] MCP server segmentation (which agent may call which tool server)
- [ ] Web dashboard for alerts, incidents and live traffic
- [ ] Recall/precision benchmark for the monitor on a public set of agent transcripts

Ideas and pull requests are welcome.

## Contributing

```bash
git clone https://github.com/Krish31595/agentwall && cd agentwall
pip install -e ".[dev]"
pytest -q
```

Keep the runtime free of dependencies, add a test for every detector or rule you add, and run `agentwall replay` on the example incident before opening a PR. New incident recordings in `examples/` are especially useful.

Found a security issue in agentwall itself? See [SECURITY.md](SECURITY.md).

## License

Apache 2.0

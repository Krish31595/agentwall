# Security policy

agentwall is a security tool, so bugs that let an agent get around it matter.

## Reporting a vulnerability

Please don't open a public issue for anything that lets an agent bypass a segment, lift a quarantine, read the provider API key, or hide activity from the audit log. Use GitHub's private vulnerability reporting instead: **Security → Report a vulnerability** on this repository.

Include the agentwall version, your policy (with tokens removed), and steps or a replay file that reproduces the problem. You should hear back within a few days.

## Scope

In scope: the egress proxy, model gateway, threat engine, misalignment monitor, policy loading and the exporters.

Known limits, which are documented and not treated as vulnerabilities: agents that ignore proxy environment variables when not run inside the Docker or Kubernetes setups from `agentwall export`, and URL paths inside TLS, which agentwall does not inspect.

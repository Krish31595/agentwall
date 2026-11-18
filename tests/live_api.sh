#!/usr/bin/env bash
# Live end-to-end test against a real model API. Needs AGENTWALL_API_KEY
# (and AGENTWALL_API_BASE if your provider is not the default upstream).
# Spends well under one cent (a few short calls to a small model).
set -euo pipefail

MODEL="${AGENTWALL_LIVE_MODEL:-openai/gpt-4o-mini}"
mkdir -p live && cd live
cat > agentwall.toml <<EOF
[defaults]
mode = "enforce"
log_path = "agentwall.log.jsonl"
upstream = "${AGENTWALL_API_BASE:-https://openrouter.ai/api/v1}"

[segments.ci]
token = "ci-token-$RANDOM$RANDOM"
egress = ["pypi.org"]
models = ["$MODEL"]
budget_usd = 0.05

[monitor]
sample_rate = 1.0
EOF
TOKEN=$(grep '^token' agentwall.toml | cut -d'"' -f2)

agentwall up > up.log 2>&1 &
UP=$!
trap 'kill $UP 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do curl -s -o /dev/null http://127.0.0.1:8898/ && break; sleep 0.5; done

fail() { echo "FAIL: $*"; echo "--- up.log"; cat up.log; exit 1; }
post() {  # model, key -> prints http code, body in /tmp/body.json
  curl -s -o /tmp/body.json -w "%{http_code}" http://127.0.0.1:8898/v1/chat/completions \
    -H "Authorization: Bearer $2" -H "Content-Type: application/json" \
    -d "{\"model\":\"$1\",\"max_tokens\":20,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the word ok. My key is AKIAABCDEFGHIJKLMNOP\"}]}"
}

echo "1. allowed model through the gateway"
code=$(post "$MODEL" "ci:$TOKEN"); [ "$code" = 200 ] || fail "expected 200, got $code: $(cat /tmp/body.json)"
grep -q '"choices"' /tmp/body.json || fail "no choices in response"

echo "2. model outside the segment is refused"
code=$(post "openai/gpt-4o" "ci:$TOKEN"); [ "$code" = 403 ] || fail "expected 403, got $code"

echo "3. bad segment token is refused"
code=$(post "$MODEL" "ci:wrong"); [ "$code" = 401 ] || fail "expected 401, got $code"

echo "4. secret was redacted and cost was tracked"
grep -q '"redacted":\["aws-access-key"\]' agentwall.log.jsonl || fail "redaction not logged"
grep -q '"cost_usd":' agentwall.log.jsonl || fail "cost not logged"

echo "5. proxy: allowlisted host passes, others are blocked"
eval "$(agentwall run ci)"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 https://pypi.org/simple/ || true)
[ "$code" = 200 ] || fail "pypi.org via proxy: expected 200, got $code"
if curl -s -o /dev/null --max-time 15 https://webhook.site/; then fail "webhook.site should be blocked"; fi
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy ALL_PROXY

echo "6. monitor sampled the exchange (sample_rate=1.0)"
sleep 3
grep -q '"kind":"monitor"' agentwall.log.jsonl || fail "monitor did not process the exchange"

agentwall status
agentwall alerts || true
echo "ALL LIVE CHECKS PASSED"

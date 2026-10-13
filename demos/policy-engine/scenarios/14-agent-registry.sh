#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
#
# The agent registry: what an agent is approved for lives in a reviewed record
# (registry/agents/hr-copilot-agent.json), and registry/sync.py makes Keycloak
# match it. This scenario shows both directions:
#
#   1. The record's facts reach the agent's token. Its SVID, presented to
#      Keycloak as a client assertion, yields a token carrying the owner, the
#      policy profile and a reference to the exact record version it was issued
#      against.
#   2. Suspending the agent stops it. The sync disables the agent's client,
#      Keycloak refuses its SVID, and the gateway's delegation for get_headcount
#      fails, so the call never reaches the tool. The record itself is not
#      edited: the suspension is a one-run override, and the agent is restored
#      afterwards.
#   3. A token the agent already holds stops working too, but it is Keycloak
#      that stops it: the gateway accepts the token and policy permits the
#      call, and the exchange is refused. The gateway does not check
#      revocation itself yet (praxis-proxy/policy#205); the agent's short token
#      lifetime bounds how long a route that never exchanges would let it in.
#   4. Lifting the suspension makes that same token valid again.
#   5. Revoking is different: tokens issued before the revocation stay invalid
#      even after the agent is reinstated, while new ones work.
#
# Needs the SPIRE overlay (WITH_SPIRE=1 ./restart.sh); skipped otherwise.

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

AGENT="hr-copilot-agent"
RECORD="$DEMO_DIR/registry/agents/$AGENT.json"
# The agent runs as this uid in the `workloads` container; SPIRE attests it.
WORKLOAD_UID="${WORKLOAD_UID:-1001}"
REALM_ISSUER="${REALM_ISSUER:-http://localhost:8081/realms/policy-demo}"
TOKEN_URL="$REALM_ISSUER/protocol/openid-connect/token"

if ! curl -sf --max-time 3 -o /dev/null http://localhost:8443/keys; then
  note "SPIRE overlay not running (no keys at localhost:8443): skipping"
  note "  run WITH_SPIRE=1 ./restart.sh to include it"
  exit 77
fi

fetch_svid() {
  "$DEMO_DIR/spire/fetch-svid.sh" "$WORKLOAD_UID" "$REALM_ISSUER" 2>/dev/null
}

agent_token() {
  curl -sf -X POST "$TOKEN_URL" \
    -d grant_type=client_credentials \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe \
    -d client_assertion="$(fetch_svid)" | jq -r '.access_token // empty'
}

call_list_open_roles() { # $1 = agent token
  RAW=$(curl -isS --max-time 20 -X POST "$GATEWAY/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $1" \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_open_roles","arguments":{}}}')
  _print_response "$RAW"
}

claim() { # $1 = token, $2 = claim name
  python3 -c '
import sys,json,base64
p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get(sys.argv[2], ""))' "$1" "$2"
}

expect_claim() { # $1 = token, $2 = claim, $3 = expected value
  local got
  got="$(claim "$1" "$2")"
  if [ "$got" = "$3" ]; then pass_ "token $2 = $3"; else fail_ "expected token $2 = '$3', got '${got:-<absent>}'"; fi
}

# Whatever happens below, leave the agent as its record says.
trap '"$DEMO_DIR/registry/sync.py" >/dev/null' EXIT

step "1. The registry's facts reach the agent's token"
"$DEMO_DIR/registry/sync.py" >/dev/null
TOKEN="$(agent_token)"
if [ -z "$TOKEN" ]; then
  fail_ "Keycloak issued no token for the agent's SVID"
  finish
fi
expect_claim "$TOKEN" azp "$AGENT"
expect_claim "$TOKEN" agent_owner "$(jq -r .owner_ref "$RECORD")"
expect_claim "$TOKEN" agent_policy_profile "$(jq -r .policy_profile_ref "$RECORD")"
REF="$(claim "$TOKEN" agent_registration_ref)"
case "$REF" in
  *"#$AGENT@"*";sha256:"*) pass_ "token agent_registration_ref names the record version and digest ($REF)" ;;
  *) fail_ "unexpected agent_registration_ref '${REF:-<absent>}'" ;;
esac
LIFETIME=$(( $(claim "$TOKEN" exp) - $(claim "$TOKEN" iat) ))
if [ "$LIFETIME" -le 300 ]; then pass_ "token lifetime ${LIFETIME}s (short, so a suspension is felt quickly)"; else fail_ "token lifetime ${LIFETIME}s, expected at most 300s"; fi

step "2. A suspended agent is refused before the call reaches the tool"
"$DEMO_DIR/registry/sync.py" --state "$AGENT=suspended" >/dev/null
reset_upstream
RAW=$(curl -isS --max-time 20 -X POST "$GATEWAY/mcp" \
  -H "Content-Type: application/json" \
  -H "X-Workload-Token: $(fetch_svid)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_headcount","arguments":{}}}')
_print_response "$RAW"
expect_violation delegation.idp_rejected
expect_upstream_calls 0

step "3. The token the agent already holds is refused at the exchange"
reset_upstream
call_list_open_roles "$TOKEN"
expect_violation delegation.idp_rejected
expect_upstream_calls 0
note "The gateway accepted this token and policy permitted the call; Keycloak refused"
note "the exchange. The gateway does not check revocation itself yet."

step "4. Lifting the suspension makes the same token valid again"
"$DEMO_DIR/registry/sync.py" >/dev/null
reset_upstream
call_list_open_roles "$TOKEN"
expect_status 200
expect_rpc_ok
expect_upstream_calls 1

step "5. Revoking invalidates earlier tokens for good; new ones still work"
"$DEMO_DIR/registry/sync.py" --state "$AGENT=revoked" >/dev/null
"$DEMO_DIR/registry/sync.py" >/dev/null   # reinstated
reset_upstream
call_list_open_roles "$TOKEN"
expect_violation delegation.idp_rejected
expect_upstream_calls 0
sleep 1   # a token issued in the revocation's second would count as earlier
reset_upstream
call_list_open_roles "$(agent_token)"
expect_status 200
expect_rpc_ok
expect_upstream_calls 1
finish

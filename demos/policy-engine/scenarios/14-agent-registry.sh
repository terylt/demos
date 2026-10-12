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
SVID="$(fetch_svid)"
TOKEN=$(curl -sf -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe \
  -d client_assertion="$SVID" | jq -r '.access_token // empty')
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
finish

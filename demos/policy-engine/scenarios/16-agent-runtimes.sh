#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
#
# One agent, several runtimes: the agent's identity is not its SPIFFE ID.
#
# A SPIFFE ID names where a workload runs. An agent is one logical identity
# that may run in several places, and its registration record lists them
# (`runtimes` in registry/agents/hr-copilot-agent.json): production, as uid
# 1001, and staging, as uid 1003. registry/sync.py gives each runtime its own
# SPIRE entry and its own Keycloak client, and every token from either carries
# the same agent_id and the same registration facts.
#
#   1. The staging runtime gets a different SPIFFE ID from production.
#   2. Its Keycloak token names the same agent (agent_id, profile) but a
#      different client (azp).
#   3. Policy decides on the agent, so list_open_roles allows it.
#
# Needs the SPIRE overlay (WITH_SPIRE=1 ./restart.sh); skipped otherwise.

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

REALM_ISSUER="${REALM_ISSUER:-http://localhost:8081/realms/policy-demo}"
TOKEN_URL="$REALM_ISSUER/protocol/openid-connect/token"

if ! curl -sf --max-time 3 -o /dev/null http://localhost:8443/keys; then
  note "SPIRE overlay not running (no keys at localhost:8443): skipping"
  note "  run WITH_SPIRE=1 ./restart.sh to include it"
  exit 77
fi

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

token_for() { # $1 = SVID; prints the Keycloak access token it buys
  curl -sf -X POST "$TOKEN_URL" \
    -d grant_type=client_credentials \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe \
    -d client_assertion="$1" | jq -r '.access_token // empty'
}

step "1. Two runtimes of hr-copilot-agent get different SPIFFE IDs"
PROD_SVID=$("$DEMO_DIR/spire/fetch-svid.sh" 1001 "$REALM_ISSUER" 2>/dev/null) || true
STAGING_SVID=$("$DEMO_DIR/spire/fetch-svid.sh" 1003 "$REALM_ISSUER" 2>/dev/null) || true
if [ -z "$PROD_SVID" ] || [ -z "$STAGING_SVID" ]; then
  fail_ "SPIRE issued no SVID to uid 1001 or 1003"
  finish
fi
expect_claim "$PROD_SVID" sub spiffe://policy.demo/ns/hr/sa/copilot
expect_claim "$STAGING_SVID" sub spiffe://policy.demo/ns/hr-staging/sa/copilot

step "2. Both tokens name the same agent; the client differs"
PROD_TOKEN="$(token_for "$PROD_SVID")"
STAGING_TOKEN="$(token_for "$STAGING_SVID")"
if [ -z "$PROD_TOKEN" ] || [ -z "$STAGING_TOKEN" ]; then
  fail_ "Keycloak issued no token for one of the runtimes"
  finish
fi
expect_claim "$PROD_TOKEN" agent_id hr-copilot-agent
expect_claim "$STAGING_TOKEN" agent_id hr-copilot-agent
expect_claim "$STAGING_TOKEN" agent_policy_profile profiles/hr-agents
expect_claim "$PROD_TOKEN" azp hr-copilot-agent.prod
expect_claim "$STAGING_TOKEN" azp hr-copilot-agent.staging

step "3. Policy decides on the agent, so the staging runtime may list open roles"
reset_upstream
RAW=$(curl -isS --max-time 20 -X POST "$GATEWAY/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $STAGING_TOKEN" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_open_roles","arguments":{}}}')
_print_response "$RAW"
expect_status 200
expect_rpc_ok
expect_no_violation
expect_upstream_calls 1
finish

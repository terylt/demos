#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
#
# Registered agents: the gateway decides from the agent's registration.
#
# Each agent presents its SPIFFE JWT-SVID to Keycloak, which issues it a token
# carrying its registration record as agent_* claims (registry/sync.py set
# that up). The agent then calls the gateway with that token, not the SVID.
# The list_open_roles route:
#
#   1. verifies the agent's Keycloak token (jwt-agent, role user), so the
#      registration claims reach policy as claim.agent_*,
#   2. permits only agents registered with the HR profile,
#   3. exchanges the agent's token for a workday-api token on the gateway's
#      own client credential.
#
# Both agents below hold valid tokens from the same registry. hr-copilot-agent
# is registered for HR tools and gets through; finance-bot is registered for
# finance and is denied before the call reaches the tool. Two more checks
# show what is not enough: a valid realm token with no registration (Bob's)
# is denied, because the rule tests for the allowed profile; and the raw SVID
# is refused outright, because it is the agent's credential for Keycloak, not
# for the gateway.
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

agent_token() { # $1 = SPIFFE ID; prints the agent's Keycloak access token
  local svid
  svid=$( (cd "$DEMO_DIR" && docker compose -f docker-compose.yml -f docker-compose.spire.yml \
            exec -T spire-server /opt/spire/bin/spire-server jwt mint \
            -spiffeID "$1" -audience "$REALM_ISSUER") 2>/dev/null | tr -d '[:space:]')
  curl -sf -X POST "$TOKEN_URL" \
    -d grant_type=client_credentials \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe \
    -d client_assertion="$svid" | jq -r '.access_token // empty'
}

call_list_open_roles() { # $1 = agent token
  RAW=$(curl -isS --max-time 20 -X POST "$GATEWAY/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $1" \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_open_roles","arguments":{}}}')
  _print_response "$RAW"
}

step "1. hr-copilot-agent (profile hr-agents) → list_open_roles with its Keycloak token"
HR_TOKEN="$(agent_token spiffe://policy.demo/agent/hr-copilot)"
if [ -z "$HR_TOKEN" ]; then
  fail_ "Keycloak issued no token for hr-copilot-agent's SVID"
  finish
fi
reset_upstream
call_list_open_roles "$HR_TOKEN"
expect_status 200
expect_rpc_ok
expect_no_violation
expect_upstream_calls 1
# The tool receives a token Keycloak minted for workday-api, not the agent's.
expect_upstream_audience workday-api
# The agent is the subject of its own call, so the global assertion names it.
expect_upstream_header x-auth-user-id "$(token_sub "$HR_TOKEN")"

step "2. finance-bot (profile finance-agents) → list_open_roles is denied by policy"
FIN_TOKEN="$(agent_token spiffe://policy.demo/agent/finance-bot)"
if [ -z "$FIN_TOKEN" ]; then
  fail_ "Keycloak issued no token for finance-bot's SVID"
  finish
fi
reset_upstream
call_list_open_roles "$FIN_TOKEN"
expect_violation agent_profile_not_permitted
expect_upstream_calls 0

step "3. Bob's user token (no registration) → list_open_roles is denied"
reset_upstream
call_list_open_roles "$(mint bob)"
expect_violation agent_profile_not_permitted
expect_upstream_calls 0

step "4. The agent's raw SVID → list_open_roles is refused at authentication"
SVID=$( (cd "$DEMO_DIR" && docker compose -f docker-compose.yml -f docker-compose.spire.yml \
          exec -T spire-server /opt/spire/bin/spire-server jwt mint \
          -spiffeID spiffe://policy.demo/agent/hr-copilot -audience "$REALM_ISSUER") 2>/dev/null | tr -d '[:space:]')
reset_upstream
call_list_open_roles "$SVID"
expect_status 401
expect_upstream_calls 0
finish

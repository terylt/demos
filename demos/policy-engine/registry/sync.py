#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Sync the agent registry into Keycloak.

Each file under registry/agents/ is one agent's registration record, shaped
after the ODIS Agent Registration Record. The attribute and claim names are
this demo's own; ODIS does not define them. The records live in Git, so a
change to an agent is a reviewed commit. This script makes Keycloak match
them: for each record it creates the agent's client, which authenticates by
the agent's SPIFFE JWT-SVID, carries the record as `registry.*` attributes, and
puts the facts a policy needs into every token issued to the agent.

    ./registry/sync.py                          sync every record
    ./registry/sync.py --state hr-copilot-agent=suspended
                                                override one agent's state for
                                                this run, without editing its
                                                record (scenario 14 uses this)

A client is enabled only while its record is `active` and not past
`valid_until`; Keycloak refuses to issue tokens to a disabled client, which is
what stops a suspended agent. Clients this script created earlier for agents
no longer in the registry are deleted.

The record version is the number of commits that touched the record's file,
with "+dirty" when the file has uncommitted changes, and the digest is SHA-256
over the record's canonical JSON (sorted keys, no spaces). Both go into the
`agent_registration_ref` claim, so a token says which version of the record it
was issued against.

Standard library only. Needs Keycloak up and the SPIFFE identity provider
registered (spire/setup-spiffe-idp.sh).
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
AGENTS = HERE / "agents"
KC = os.environ.get("KC", "http://localhost:8081")
REALM = os.environ.get("REALM", "policy-demo")
ADMIN = os.environ.get("ADMIN", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW", "admin")
MANAGED = "registry.managed"

# Record fields copied onto the client as `registry.<field>` attributes.
ATTRIBUTES = [
    "schema_version", "lifecycle_state", "owner_ref", "sponsor_ref",
    "policy_profile_ref", "trust_domain", "valid_until",
]
# Record fields put into the agent's tokens, as claim name -> field.
CLAIMS = {
    "agent_owner": "owner_ref",
    "agent_policy_profile": "policy_profile_ref",
    "agent_trust_domain": "trust_domain",
}


def call(method, path, token=None, body=None, form=None):
    url = f"{KC}{path}"
    headers = {}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        sys.exit(f"sync: {method} {path} failed: {e.code} {e.read().decode(errors='replace')}")


def admin_token():
    resp = call("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN, "password": ADMIN_PW,
    })
    return resp["access_token"]


def version_of(path):
    """Commits that touched the record, plus "+dirty" if it has uncommitted edits."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=HERE, capture_output=True, text=True)
    count = git("rev-list", "--count", "HEAD", "--", str(path)).stdout.strip() or "0"
    tracked = git("ls-files", "--error-unmatch", str(path)).returncode == 0
    dirty = not tracked or bool(git("status", "--porcelain", "--", str(path)).stdout.strip())
    return f"{count}+dirty" if dirty else count


def digest_of(record):
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def is_enabled(record, state):
    if state != "active":
        return False
    valid_until = datetime.datetime.fromisoformat(record["valid_until"].replace("Z", "+00:00"))
    return datetime.datetime.now(datetime.timezone.utc) < valid_until


def hardcoded(name, value):
    return {
        "name": name, "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {
            "claim.name": name, "claim.value": value, "jsonType.label": "String",
            "access.token.claim": "true", "id.token.claim": "false",
            "introspection.token.claim": "true",
        },
    }


def client_for(record, state, version, digest):
    agent = record["agent_id"]
    attributes = {f"registry.{k}": str(record[k]) for k in ATTRIBUTES}
    attributes.update({
        MANAGED: "true",
        "registry.lifecycle_state": state,
        "registry.record_version": version,
        "registry.record_digest": digest,
        "registry.approved_software_refs": json.dumps(record["approved_software_refs"]),
        # Federated client authentication: Keycloak accepts the agent's SVID
        # from this identity provider, and picks this client by the SVID's sub.
        "jwt.credential.issuer": record["approved_runtime_issuer"],
        "jwt.credential.sub": record["spiffe_id"],
    })
    mappers = [hardcoded(claim, record[field]) for claim, field in CLAIMS.items()]
    mappers.append(hardcoded("agent_registration_ref", f"{KC}/realms/{REALM}#{agent}@{version};{digest}"))
    # The clients allowed to exchange this agent's tokens must be in their
    # audience, or Keycloak refuses the exchange.
    for i, aud in enumerate(record["provider_entitlements"]["exchange_clients"]):
        mappers.append({
            "name": f"exchange-audience-{i}", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": aud,
                       "access.token.claim": "true", "id.token.claim": "false"},
        })
    return {
        "clientId": agent, "enabled": is_enabled(record, state),
        "protocol": "openid-connect", "publicClient": False,
        "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "clientAuthenticatorType": "federated-jwt",
        "attributes": attributes, "protocolMappers": mappers,
    }


def main():
    parser = argparse.ArgumentParser(description="Sync the agent registry into Keycloak.")
    parser.add_argument("--state", action="append", default=[], metavar="AGENT=STATE",
                        help="override one agent's lifecycle state for this run")
    args = parser.parse_args()
    overrides = dict(s.split("=", 1) for s in args.state)

    token = admin_token()
    base = f"/admin/realms/{REALM}/clients"
    wanted = set()
    for path in sorted(AGENTS.glob("*.json")):
        record = json.loads(path.read_text())
        agent = record["agent_id"]
        wanted.add(agent)
        state = overrides.get(agent, record["lifecycle_state"])
        version, digest = version_of(path), digest_of(record)
        client = client_for(record, state, version, digest)
        # Recreate rather than update: Keycloak's client PUT does not reliably
        # replace protocol mappers, and recreating keeps this idempotent.
        for existing in call("GET", f"{base}?clientId={urllib.parse.quote(agent)}", token):
            call("DELETE", f"{base}/{existing['id']}", token)
        call("POST", base, token, body=client)
        print(f"sync: {agent} v{version} {state} "
              f"({'enabled' if client['enabled'] else 'disabled'}) {digest[:19]}")

    for existing in call("GET", f"{base}?max=1000", token):
        if existing.get("attributes", {}).get(MANAGED) == "true" and existing["clientId"] not in wanted:
            call("DELETE", f"{base}/{existing['id']}", token)
            print(f"sync: {existing['clientId']} removed (no longer in the registry)")


if __name__ == "__main__":
    main()

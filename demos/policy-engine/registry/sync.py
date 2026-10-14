#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Sync the agent registry into SPIRE and Keycloak.

Each file under registry/agents/ is one agent's registration record, shaped
after the ODIS Agent Registration Record. The attribute and claim names are
this demo's own; ODIS does not define them. The records live in Git, so a
change to an agent is a reviewed commit.

An agent is one logical identity that may run in several places. Each entry
in a record's `runtimes` is one of them: a SPIFFE ID and the SPIRE selectors
of the processes that may hold it. For each runtime this script makes

  - a SPIRE registration entry, so SPIRE issues that SPIFFE ID to a process it
    attests with those selectors, and to no other process; and
  - a Keycloak client `<agent_id>.<runtime>`, which authenticates by an SVID
    with that SPIFFE ID, carries the record as `registry.*` attributes, and
    puts the facts a policy needs into every token, including `agent_id`, so
    a policy names the agent rather than one of its runtimes.

SPIRE issues SVIDs to every registered runtime whatever the agent's state: an
SVID says which workload this is, not what it may do. The lifecycle below is
enforced at Keycloak, where the agent's authority comes from.

    ./registry/sync.py                          sync every record
    ./registry/sync.py --state hr-copilot-agent=suspended
                                                override one agent's state for
                                                this run, without editing its
                                                record (scenario 14 uses this)

A client is enabled only while its record is `active` and not past
`valid_until`. Disabling it is a suspension: Keycloak issues the agent no new
tokens, treats the ones it holds as inactive, and refuses to exchange them, and
re-enabling it makes those same tokens valid again. A `revoked` record also
sets the client's "not before" time, which invalidates every token issued
before it for good, even if the agent is later reinstated. Agent tokens last
TOKEN_LIFESPAN seconds, which bounds how long a gateway that does not go back
to Keycloak keeps accepting a suspended agent's token. Clients and SPIRE
entries this script created earlier for runtimes no longer in the registry
are deleted.

Clients are updated in place, so an agent keeps its client and service account
across syncs and a suspension can be lifted.

The record version is the number of commits that touched the record's file,
with "+dirty" when the file has uncommitted changes, and the digest is SHA-256
over the record's canonical JSON (sorted keys, no spaces). Both go into the
`agent_registration_ref` claim, so a token says which version of the record it
was issued against.

Standard library only. Needs Keycloak and the SPIRE overlay up
(WITH_SPIRE=1 ./restart.sh runs this), with the SPIFFE identity provider
registered (spire/setup-spiffe-idp.sh). SPIRE entries are made with the
spire-server CLI through docker compose, and tagged with the hint
`registry:<agent_id>` so this script can tell them from other entries.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
AGENTS = HERE / "agents"
DEMO = HERE.parent
KC = os.environ.get("KC", "http://localhost:8081")
REALM = os.environ.get("REALM", "policy-demo")
ADMIN = os.environ.get("ADMIN", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW", "admin")
MANAGED = "registry.managed"
# The node the SPIRE agent joined as (restart.sh's join token); every runtime's
# entry is issued through it.
PARENT_ID = os.environ.get("PARENT_ID", "spiffe://policy.demo/node/demo-host")
HINT = "registry:"
# Agent access token lifetime. The agent can always get a new token with its
# SVID, so this costs nothing and caps how long a token outlives a suspension.
TOKEN_LIFESPAN = int(os.environ.get("TOKEN_LIFESPAN", "300"))

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


def spire(*args):
    cmd = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.spire.yml",
           "exec", "-T", "spire-server", "/opt/spire/bin/spire-server", *args]
    out = subprocess.run(cmd, cwd=DEMO, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"sync: spire-server {args[0]} {args[1]} failed: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout


def spiffe_id(sid):
    return f"spiffe://{sid['trust_domain']}{sid['path']}"


def sync_spire_entries(wanted):
    """Make SPIRE's registry-owned entries match `wanted`, a set of
    (agent_id, spiffe_id, selectors) tuples. Unchanged entries are left alone,
    so a sync does not interrupt SVIDs already being issued."""
    entries = json.loads(spire("entry", "show", "-output", "json")).get("entries") or []
    have = {}
    for e in entries:
        if not e.get("hint", "").startswith(HINT):
            continue
        key = (e["hint"][len(HINT):], spiffe_id(e["spiffe_id"]),
               tuple(sorted(f"{s['type']}:{s['value']}" for s in e["selectors"])))
        if key in wanted and spiffe_id(e["parent_id"]) == PARENT_ID and key not in have:
            have[key] = e["id"]
        else:
            spire("entry", "delete", "-entryID", e["id"])
    for agent, sid, selectors in sorted(wanted - have.keys()):
        args = ["entry", "create", "-parentID", PARENT_ID, "-spiffeID", sid, "-hint", HINT + agent]
        for sel in selectors:
            args += ["-selector", sel]
        spire(*args)


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


def client_for(record, runtime, state, version, digest):
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
        "jwt.credential.sub": runtime["spiffe_id"],
        "registry.agent_id": agent,
        "registry.runtime": runtime["name"],
        "access.token.lifespan": str(TOKEN_LIFESPAN),
    })
    mappers = [hardcoded("agent_id", agent)]
    mappers += [hardcoded(claim, record[field]) for claim, field in CLAIMS.items()]
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
        "clientId": f"{agent}.{runtime['name']}", "enabled": is_enabled(record, state),
        "protocol": "openid-connect", "publicClient": False,
        "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "clientAuthenticatorType": "federated-jwt",
        "attributes": attributes, "protocolMappers": mappers,
    }


def main():
    parser = argparse.ArgumentParser(description="Sync the agent registry into SPIRE and Keycloak.")
    parser.add_argument("--state", action="append", default=[], metavar="AGENT=STATE",
                        help="override one agent's lifecycle state for this run")
    args = parser.parse_args()
    overrides = dict(s.split("=", 1) for s in args.state)

    token = admin_token()
    base = f"/admin/realms/{REALM}/clients"
    wanted, entries = set(), set()
    for path in sorted(AGENTS.glob("*.json")):
        record = json.loads(path.read_text())
        agent = record["agent_id"]
        state = overrides.get(agent, record["lifecycle_state"])
        version, digest = version_of(path), digest_of(record)
        for runtime in record["runtimes"]:
            entries.add((agent, runtime["spiffe_id"], tuple(sorted(runtime["selectors"]))))
            client = client_for(record, runtime, state, version, digest)
            wanted.add(client["clientId"])
            sync_client(token, base, client, state)
        print(f"sync: {agent} v{version} {state} "
              f"({'enabled' if is_enabled(record, state) else 'disabled'}) {digest[:19]} "
              f"runtimes: {', '.join(r['name'] for r in record['runtimes'])}")
    sync_spire_entries(entries)

    for existing in call("GET", f"{base}?max=1000", token):
        if existing.get("attributes", {}).get(MANAGED) == "true" and existing["clientId"] not in wanted:
            call("DELETE", f"{base}/{existing['id']}", token)
            print(f"sync: {existing['clientId']} removed (no longer in the registry)")


def sync_client(token, base, client, state):
    existing = call("GET", f"{base}?clientId={urllib.parse.quote(client['clientId'])}", token)
    if existing:
        cid = existing[0]["id"]
        # Update in place, keeping the client and its service account, so a
        # suspension can be lifted and the agent's tokens become valid again.
        update = {**existing[0], **{k: v for k, v in client.items() if k != "protocolMappers"}}
        update["attributes"] = {**existing[0].get("attributes", {}), **client["attributes"]}
    else:
        call("POST", base, token, body=client)
        cid = call("GET", f"{base}?clientId={urllib.parse.quote(client['clientId'])}", token)[0]["id"]
        update = call("GET", f"{base}/{cid}", token)
    if state == "revoked":
        # Tokens issued before this instant are invalid from now on. Set on
        # every revoke, so a second revocation covers tokens issued since
        # the first; the disabled client issues none in the meantime.
        update["notBefore"] = int(time.time())
    call("PUT", f"{base}/{cid}", token, body=update)
    # The client PUT does not reliably replace protocol mappers, so they
    # are replaced one by one.
    for mapper in call("GET", f"{base}/{cid}/protocol-mappers/models", token):
        call("DELETE", f"{base}/{cid}/protocol-mappers/models/{mapper['id']}", token)
    for mapper in client["protocolMappers"]:
        call("POST", f"{base}/{cid}/protocol-mappers/models", token, body=mapper)


if __name__ == "__main__":
    main()

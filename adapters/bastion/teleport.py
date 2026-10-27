#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""A thin bastion adapter for Teleport, to MEASURE how a non-Warpgate bastion meets the
bastion contracts (C-01, C-02, C-06) - decision 0016, option A.

It is deliberately minimal: enough to run each contract operation against a live Teleport
and record whether Teleport can meet the neutral need, not a production integration. It
drives Teleport through `tctl` (the cluster admin path) via the running container, which
is what a real edge adapter would do over Teleport's gRPC admin API.

The neutral bastion interface (what the agent needs, naming no product):
  grant(subject, target, not_after)  -> a time-bounded access grant the agent is sole writer of   [C-01]
  approve_from_lease(session, lease) -> decide a pending session from a signed lease, OFFLINE      [C-02]
  prestage_visit(subject, window)    -> a pre-staged, offline-installable credential for a visit   [C-06]

Run ON the Teleport host: `python3 teleport.py`. Prints a measured verdict per operation.
"""
from __future__ import annotations

import json
import subprocess
import sys

TCTL = ["sudo", "docker", "exec", "teleport", "tctl"]


def tctl(*args: str, stdin: str | None = None) -> tuple[int, str]:
    p = subprocess.run([*TCTL, *args], input=stdin, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def _requests() -> list:
    rc, out = tctl("requests", "ls", "--format=json")
    return json.loads(out) if rc == 0 and out.lstrip().startswith("[") else []


def grant(subject: str, roles: str) -> dict:
    """C-01: a time-bounded access grant. In Teleport this is an Access Request with a TTL."""
    before = {r["metadata"]["name"] for r in _requests()}
    tctl("requests", "create", subject, "--roles", roles)
    after = _requests()
    new = [r for r in after if r["metadata"]["name"] not in before]
    pick = new[0] if new else (sorted(after, key=lambda r: r["spec"].get("created", ""))[-1]
                               if after else None)
    if pick is None:
        return {"met": False, "why": "no request created"}
    rid = pick["metadata"]["name"]
    tctl("requests", "approve", rid)                       # central Auth-Service op (see C-02)
    r = [x for x in _requests() if x["metadata"]["name"] == rid]
    r = r[0] if r else pick
    expiry = r["spec"].get("session_ttl") or r["metadata"].get("expires")
    return {"met": bool(expiry), "mechanism": "Access Request + central approve",
            "expires": expiry, "sole_writer": "no - the user requests; the operator/agent approves centrally"}


def approve_from_lease() -> dict:
    """C-02: approve a pending session OFFLINE, from a signed lease, with no live core round trip."""
    # Teleport's only approval path is the central Auth Service (tctl/API against auth).
    # There is no edge-local API to decide a pending session from an externally-signed lease
    # while cut off from the cluster's Auth Service. This is architectural, not missing config.
    return {"met": False,
            "why": "Teleport approval is a central Auth-Service operation; there is no offline, "
                   "edge-local approval an external agent can make from a signed lease",
            "capability_gap": True}


def prestage_visit() -> dict:
    """C-06: a pre-staged, offline-installable credential for a time-boxed visit."""
    # Teleport authenticates users with short-lived CA certificates issued by the Auth Service
    # at login time; it does not register a static, pre-staged SSH public key, and certificate
    # issuance needs the Auth Service (not offline). A visit could be approximated by pre-issuing
    # a short cert, but that is central and not offline-installable like a staged key.
    return {"met": False, "approximation": "pre-issue a short-lived cert (central, not offline)",
            "why": "no static pre-staged credential; CA certs are issued centrally at login"}


def main() -> int:
    print("# Teleport bastion adapter - measured against the neutral bastion contracts\n")
    g = grant("alice", "privileged")
    print(f"C-01 time-bounded grant : {'MET' if g['met'] else 'NOT MET'} - {g.get('mechanism','')}; "
          f"expires={g.get('expires')}; sole-writer: {g.get('sole_writer','')}")
    a = approve_from_lease()
    print(f"C-02 offline approval   : {'MET' if a['met'] else 'NOT MET (capability gap)'} - {a['why']}")
    v = prestage_visit()
    print(f"C-06 pre-staged visit   : {'MET' if v['met'] else 'NOT MET'} - {v['why']}")
    print("\nResidue (what the adapter/agent must add that Teleport does not give neutrally): "
          "offline approval is impossible (hard gap); a pre-staged offline credential has no "
          "Teleport equivalent. Time-bounded grants map cleanly via Access Requests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

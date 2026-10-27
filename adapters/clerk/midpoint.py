#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""A thin clerk adapter: midPoint -> the edge-decision interface (EDI, decision 0017), to MEASURE the residue.

The point of option A: a general IGA (midPoint) natively gives time-bounded, revocable grants, but the EDI the agent
consumes needs much more. This adapter reads midPoint grants and emits an EDI artifact, and reports exactly what it
had to ADD (the residue) versus what midPoint gave. The residue is the measure of how KeyClerk-shaped the clerk role is.

It runs offline against a representative midPoint REST payload (the documented `users/{oid}` shape with assignment
`activation/validFrom/validTo`); the residue is structural, not data-dependent, so a live call would not change it.
A live midPoint only confirms the read side (blocked here by midPoint's first-login password-change quirk).

  native from midPoint : the decisions (subject, target, validity window)
  residue the adapter adds : serial, per-class horizons, sealed ceiling, signature, pinned-key verification,
                             enrolment binding  (none of which a general IGA provides)
"""
from __future__ import annotations

import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- INPUT: a representative midPoint REST payload (GET /ws/rest/users/{oid}) ---------------------------------------
# A user with a time-bounded role assignment. This is midPoint's native model; nothing here is KeyClerk-shaped.
MIDPOINT_USER = {
    "user": {
        "oid": "a1b2c3d4-0000-0000-0000-000000000002",
        "name": "visitor1",
        "assignment": [{
            "targetRef": {"oid": "00000000-0000-0000-0000-000000000008", "type": "RoleType"},
            "activation": {"validFrom": "2026-10-24T00:00:00.000Z", "validTo": "2026-10-25T00:00:00.000Z"},
        }],
    }
}


def read_grants(mp_user: dict) -> list[dict]:
    """NATIVE: what midPoint gives directly - subject, target, validity window."""
    u = mp_user["user"]
    out = []
    for a in u.get("assignment", []):
        act = a.get("activation", {})
        out.append({
            "subject": u["name"],
            "target": a["targetRef"]["oid"],
            "not_before": act.get("validFrom"),
            "not_after": act.get("validTo"),
        })
    return out


# --- RESIDUE: everything below is what the adapter must ADD; midPoint provides none of it -----------------------------
def emit_edi(grants: list[dict], *, edge_id: str, ceiling: dict, serial: int,
            horizons: dict, signing_key: Ed25519PrivateKey) -> dict:
    body = {
        "edge_id": edge_id,          # residue: enrolment binding
        "serial": serial,            # residue: monotonic serial (rollback/replay protection)
        "horizons": horizons,        # residue: per-class horizons (bounded offline validity)
        "ceiling": ceiling,          # residue: the officer-sealed per-edge ceiling
        "decisions": grants,         # native (from midPoint)
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    sig = signing_key.sign(payload)  # residue: signature over the whole artifact
    return {"body": body, "signature": sig.hex()}


def verify_edi(edi: dict, pinned_pub, *, edge_id: str, last_serial: int, ceiling_targets: set) -> list[str]:
    """The agent's OFFLINE verification - the whole point of the EDI (no live core)."""
    problems = []
    body = edi["body"]
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    try:
        pinned_pub.verify(bytes.fromhex(edi["signature"]), payload)
    except Exception:
        problems.append("signature does not verify against the pinned key")
    if body["serial"] <= last_serial:
        problems.append("serial is not above the last applied")
    if body["edge_id"] != edge_id:
        problems.append("not addressed to this edge")
    for d in body["decisions"]:
        if d["target"] not in ceiling_targets:
            problems.append(f"decision target {d['target']} outside the sealed ceiling")
    return problems


def main() -> int:
    grants = read_grants(MIDPOINT_USER)
    key = Ed25519PrivateKey.generate()
    ceiling = {"targets": ["00000000-0000-0000-0000-000000000008"], "max_lease_hours": 24}
    edi = emit_edi(grants, edge_id="edge-001", ceiling=ceiling, serial=7,
                   horizons={"standing": "2026-11-01T00:00:00Z"}, signing_key=key)
    problems = verify_edi(edi, key.public_key(), edge_id="edge-001", last_serial=6,
                          ceiling_targets=set(ceiling["targets"]))

    print("# midPoint -> EDI clerk adapter - residue measurement\n")
    print(f"decisions read natively from midPoint : {len(grants)} "
          f"(subject/target/validity - midPoint activation validFrom/validTo)")
    print("properties the adapter had to ADD (residue, none native to midPoint):")
    for p in ["enrolment binding (edge_id)", "monotonic serial", "per-class horizons",
              "officer-sealed ceiling", "ed25519 signature over the artifact",
              "offline pinned-key verification (agent side)"]:
        print(f"  - {p}")
    print(f"\nagent offline verification of the emitted EDI: "
          f"{'PASS (no live core needed)' if not problems else 'FAIL: ' + '; '.join(problems)}")
    print("\nVerdict: midPoint supplies 1 of the 6 EDI properties (the decisions). The adapter supplies the five "
          "security properties that make the artifact safe to apply offline - i.e. the clerk role is KeyClerk-shaped "
          "in substance; a general IGA is a data source behind an emitter that is, functionally, a re-implementation "
          "of KeyClerk's edge emitter (decision 0017, 'consider the opposite').")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())

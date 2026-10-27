#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Solution-agnostic conformance matrix (decision 0016), config-as-code.

Reads model/contracts.yaml, model/adapters.yaml and model/profiles.yaml and derives, for each profile, which
contracts hold. A contract holds iff its provider role is bound to an adapter that satisfies it and every swappable
role it consumes is bound.

Fails (exit 1) if:
  - the reference profile does not hold every contract (the shipped shape must be complete),
  - a stand-in adapter does not cover its role's full provider-contract set (it could not prove agnosticism),
  - a provider-contract is satisfied by no stand-in at all (it is product-shaped - reword it).

Everything else - a reduced profile that drops contracts on purpose - is reported, not failed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

MODEL = Path(__file__).resolve().parent.parent / "model"
ALWAYS_PRESENT = {"agent", "person", "host"}      # never swapped, never `none`
SWAPPABLE = {"clerk", "bastion"}                  # the roles a profile may set to `none`


def as_list(v):
    return v if isinstance(v, list) else [v]


def load(name):
    return yaml.safe_load((MODEL / name).read_text(encoding="utf-8"))


def main() -> int:
    contracts = load("contracts.yaml")["contracts"]
    adapters = {a["id"]: a for a in load("adapters.yaml")["adapters"]}
    pf = load("profiles.yaml")
    defaults, profiles = pf["defaults"], pf["profiles"]

    # role -> set of provider-contract ids
    provided: dict[str, set] = {}
    for k in contracts:
        for role in as_list(k["provider"]):
            provided.setdefault(role, set()).add(k["id"])

    def satisfies(adapter_id, cid):
        return adapter_id in adapters and cid in adapters[adapter_id].get("satisfies", [])

    def bindings(profile):
        b = dict(defaults)
        b.update(profile["bind"])
        return b

    def present(b, role):
        return role in ALWAYS_PRESENT or b.get(role) not in (None, "none")

    def status(b, k):
        for role in as_list(k["provider"]):
            if not present(b, role):
                return "absent", f"provider {role} absent"
            if not satisfies(b.get(role), k["id"]):
                return "gap", f"{b.get(role)} lacks {k['id']}"
        for role in as_list(k["consumer"]):
            if role in SWAPPABLE and not present(b, role):
                return "degraded", f"consumer {role} absent"
        return "hold", ""

    failures, matrix = [], {}
    for p in profiles:
        b = bindings(p)
        row = {k["id"]: status(b, k) for k in contracts}
        matrix[p["id"]] = row
        held = [c for c, (s, _) in row.items() if s == "hold"]
        drop = [f"{c}({r})" for c, (s, r) in row.items() if s != "hold"]
        tag = " [reference]" if p.get("optimised") else ""
        print(f"{p['id']:32}{tag:12} {len(held):2}/{len(contracts)} hold" +
              (f" | reduced: {', '.join(drop)}" if drop else ""))
        if p.get("optimised") and drop:
            failures.append(f"reference profile {p['id']} does not hold: {', '.join(drop)}")

    # every stand-in must cover its role; every provider-contract must have a stand-in
    covered_by_standin: set = set()
    for a in adapters.values():
        if a["kind"] == "stand-in":
            need = provided.get(a["role"], set())
            have = set(a.get("satisfies", []))
            if not need <= have:
                failures.append(f"stand-in {a['id']} misses {sorted(need - have)} of role {a['role']}")
            covered_by_standin |= have
    for role in SWAPPABLE:
        for cid in provided.get(role, set()):
            if cid not in covered_by_standin:
                failures.append(f"{cid} ({role}) is satisfied by no stand-in - it is product-shaped")

    print()
    if failures:
        print("CONFORMANCE FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OK: {len(profiles)} profiles, reference complete, every swappable role proven agnostic by a stand-in.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

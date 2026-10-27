# SPDX-License-Identifier: EUPL-1.2
"""The conformance matrix holds: the reference profile is complete and every swappable role is proven agnostic."""
import tools.check_conformance as cc


def test_conformance_matrix_passes():
    assert cc.main() == 0


def test_reference_profile_holds_every_contract():
    contracts = cc.load("contracts.yaml")["contracts"]
    adapters = {a["id"]: a for a in cc.load("adapters.yaml")["adapters"]}
    pf = cc.load("profiles.yaml")
    ref = next(p for p in pf["profiles"] if p.get("optimised"))
    b = dict(pf["defaults"]); b.update(ref["bind"])

    def present(role):
        return role in cc.ALWAYS_PRESENT or b.get(role) not in (None, "none")

    for k in contracts:
        for role in cc.as_list(k["provider"]):
            assert present(role), f"{k['id']}: reference leaves provider {role} unbound"
            assert k["id"] in adapters[b[role]]["satisfies"], f"{k['id']}: {b[role]} does not satisfy it"


def test_reduced_profiles_drop_the_expected_contracts():
    pf = cc.load("profiles.yaml")
    contracts = cc.load("contracts.yaml")["contracts"]
    provided = {}
    for k in contracts:
        for role in cc.as_list(k["provider"]):
            provided.setdefault(role, set()).add(k["id"])

    names = {p["id"] for p in pf["profiles"]}
    # the operator's cases are all present
    for want in ("reference", "only-bastion", "only-clerk",
                 "other-iga-1-warpgate", "other-iga-2-warpgate",
                 "other-iga-1-other-bastion-1", "other-iga-2-other-bastion-2"):
        assert want in names, f"missing profile {want}"

    # only-bastion must drop the clerk-provided contract (C-04)
    only_bastion = next(p for p in pf["profiles"] if p["id"] == "only-bastion")
    assert only_bastion["bind"]["clerk"] == "none"
    assert "C-04" in provided["clerk"]

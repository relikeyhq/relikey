# SPDX-License-Identifier: EUPL-1.2
"""The model check passes on the shipped model and catches the breaches it exists for."""
import copy

import pytest
import yaml

import tools.check_model as cm


def test_shipped_model_has_no_errors():
    errors, _ = cm.check()
    assert errors == []


@pytest.fixture
def patched(monkeypatch):
    """Replace one model file's content for a single test."""
    original = cm.load

    def apply(name, mutate):
        data = copy.deepcopy(original(name))
        mutate(data)
        monkeypatch.setattr(cm, "load", lambda n: data if n == name else original(n))

    return apply


def test_a_flow_into_the_legacy_system_around_the_bastion_is_refused(patched):
    patched("flows.yaml", lambda d: d["flows"].append(
        {"id": "F-99", "from": "person", "to": "legacy", "protocol": "rdp", "port": 3389, "purpose": "shortcut"}))
    errors, _ = cm.check()
    assert any("F-99" in e and "decision 0002" in e for e in errors)


def test_the_legacy_system_cannot_reach_anything_but_the_facade(patched):
    patched("flows.yaml", lambda d: d["flows"].append(
        {"id": "F-98", "from": "legacy", "to": "org-store", "protocol": "https", "port": 443, "purpose": "phone home"}))
    errors, _ = cm.check()
    assert any("F-98" in e and "way out" in e for e in errors)


def test_an_unpinned_image_is_refused(patched):
    patched("components.yaml", lambda d: d["components"][0].update(version=None))
    errors, _ = cm.check()
    assert any("broker" in e and "pin" in e for e in errors)


def test_a_pattern_naming_a_missing_flow_is_refused(patched):
    patched("patterns.yaml", lambda d: d["patterns"][0]["flows"].append("F-77"))
    errors, _ = cm.check()
    assert any("F-77" in e for e in errors)


def test_every_open_decision_has_a_lean_or_options():
    for d in yaml.safe_load((cm.MODEL / "open-decisions.yaml").read_text(encoding="utf-8"))["open"]:
        assert d.get("question") and (d.get("lean") or d.get("options")), d["id"]


def test_the_core_may_not_open_a_connection_into_the_edge(patched):
    patched("flows.yaml", lambda d: d["flows"].append(
        {"id": "F-97", "from": "clerk", "to": "agent", "protocol": "https", "port": 9000, "purpose": "push"}))
    errors, _ = cm.check()
    assert any("F-97" in e and "decision 0005" in e for e in errors)


def test_an_edge_that_outgrows_the_switch_profile_is_refused(patched):
    patched("components.yaml", lambda d: next(c for c in d["components"] if c["id"] == "bastion")
            ["footprint"].update(ram_mb=400))
    errors, _ = cm.check()
    assert any("switch-app-hosting" in e and "memory" in e for e in errors)


def _switch(d):
    return next(p for p in d["profiles"] if p["id"] == "switch-app-hosting")


def test_the_switch_profile_overrun_is_a_recorded_gap_not_an_error():
    errors, warnings = cm.check()
    assert not any("switch-app-hosting" in e for e in errors)
    assert any("switch-app-hosting" in w and "known gap #62" in w for w in warnings)


def test_without_its_known_gap_the_switch_overrun_is_refused(patched):
    patched("footprint.yaml", lambda d: _switch(d).pop("known_gap"))
    errors, _ = cm.check()
    assert any("switch-app-hosting" in e and "memory" in e for e in errors)


@pytest.mark.parametrize("field, value, says", [
    ("issue", None, "names no issue number"),
    ("issue", "62", "names no issue number"),
    ("issue", 0, "names no issue number"),
    ("until", None, "names no release"),
    ("waits_on", "R-99", "not open in open-decisions.yaml"),
    ("ram_mb", None, "records no ram_mb"),
])
def test_a_known_gap_missing_its_issue_release_or_open_decision_is_refused(patched, field, value, says):
    patched("footprint.yaml", lambda d: _switch(d)["known_gap"].update({field: value}))
    errors, _ = cm.check()
    assert any("switch-app-hosting: known_gap" in e and says in e for e in errors)


def test_an_edge_growing_past_its_known_gap_is_refused(patched):
    patched("components.yaml", lambda d: next(c for c in d["components"] if c["id"] == "proxy")
            ["footprint"].update(ram_mb=60))
    errors, _ = cm.check()
    assert any("recorded by switch-app-hosting's known gap" in e for e in errors)


def test_a_known_gap_on_an_edge_that_fits_again_is_refused(patched):
    patched("components.yaml", lambda d: next(c for c in d["components"] if c["id"] == "proxy")
            ["footprint"].update(ram_mb=15))
    errors, _ = cm.check()
    assert any("fits the 256 MB budget again; remove the gap" in e for e in errors)


def test_keycloak_on_the_edge_breaks_the_budget(patched):
    patched("components.yaml", lambda d: next(c for c in d["components"] if c["id"] == "broker").update(tier="edge"))
    errors, _ = cm.check()
    assert any("memory" in e for e in errors)


def test_a_stretch_profile_only_warns(patched):
    _, warnings = cm.check()
    assert any("armv7" in w and "router-container" in w for w in warnings)


def test_a_question_named_only_by_a_proposed_record_is_not_decided(tmp_path, monkeypatch):
    # R-14 is closed by accepted decision 0007; R-99 appears nowhere open and in no accepted record.
    errors, _ = cm.check()
    assert not any("R-14" in e for e in errors)
    decisions = cm.ROOT / "docs" / "decisions"
    probe = decisions / "9999-probe.md"
    probe.write_text("# probe\n\n- Status: proposed\n\nMentions R-99.\n", encoding="utf-8")
    try:
        errors, _ = cm.check()
        assert any("R-99" in e and "accepted" in e for e in errors)
    finally:
        probe.unlink()


def test_a_pattern_path_that_is_not_walkable_is_refused(patched):
    patched("patterns.yaml", lambda d: d["patterns"][0].update(path=["person", "facade"]))
    errors, _ = cm.check()
    assert any("P-A" in e and "person -> facade" in e for e in errors)


def test_a_loopback_port_also_served_to_a_network_is_refused(patched):
    patched("flows.yaml", lambda d: d["flows"].append(
        {"id": "F-96", "from": "legacy", "to": "facade", "protocol": "https", "port": 17170, "purpose": "leak"}))
    errors, _ = cm.check()
    assert any("F-96" in e and "loopback-only" in e for e in errors)


def test_only_a_person_can_be_a_physical_path(patched):
    patched("flows.yaml", lambda d: d["flows"].append(
        {"id": "F-95", "from": "agent", "to": "legacy", "medium": "physical", "protocol": "x", "port": 1,
         "purpose": "smuggle"}))
    errors, _ = cm.check()
    assert any("F-95" in e and "physical" in e for e in errors)


def test_a_loopback_flow_cannot_cross_hosts(patched):
    patched("flows.yaml", lambda d: d["flows"].append(
        {"id": "F-94", "from": "clerk", "to": "facade", "protocol": "https", "port": 1, "scope": "loopback",
         "purpose": "remote admin"}))
    errors, _ = cm.check()
    assert any("F-94" in e and "crosses hosts" in e for e in errors)


def test_the_docs_are_scanned_for_deployment_names():
    assert "docs/decisions/*.md" in cm.NAME_SCAN_GLOBS and "README.md" in cm.NAME_SCAN_GLOBS


def _component(d, cid):
    return next(c for c in d["components"] if c["id"] == cid)


def test_a_deployed_image_no_component_names_is_refused(patched):
    patched("components.yaml", lambda d: _component(d, "proxy").update(image=None, version=None, digest=None))
    errors, _ = cm.check()
    assert any("deploy/edge/compose.yaml front" in e and "no edge component" in e for e in errors)


def test_a_deployed_digest_the_model_does_not_pin_is_refused(patched):
    patched("components.yaml", lambda d: _component(d, "facade").update(digest=None))
    errors, _ = cm.check()
    assert any("deploy/edge/compose.yaml facade" in e and "component facade pins" in e for e in errors)


def test_a_deployed_tag_of_another_release_is_refused(patched):
    patched("components.yaml", lambda d: _component(d, "mirror").update(version="v2.1.21"))
    errors, _ = cm.check()
    assert any("deploy/core/compose.yaml mirror" in e and "same release" in e for e in errors)

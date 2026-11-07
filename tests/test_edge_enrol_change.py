# SPDX-License-Identifier: EUPL-1.2
"""deploy/edge/enrol_change.py writes the enrol_edge change from the signed statement and the targets file (rc.4 walk
W2, #177), so its fields are what the officer and the edge signed; it refuses a statement the desk would refuse."""
import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OFFICER, EDGE, UNLOCK = "a" * 64, "b" * 64, "BK" + "x" * 85
TARGETS = [{"name": "plc-ssh", "role": "plc-operators", "ssh": {"host": "10.0.0.5", "username": "plc"}, "host_key": "k"}]


def load():
    spec = importlib.util.spec_from_file_location("enrol_change", ROOT / "deploy" / "edge" / "enrol_change.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def statement(officer="op:3cef5026-60dd-41ff-9023-05bd85f490f4", signers=(OFFICER, EDGE), unlock=UNLOCK):
    says = {"edge": "plant-a", "format": "kc-edge-officer-v2", "officer": officer, "officer_key": OFFICER,
            "purpose": "enrolment", "nodes": [{"enrolment_key": EDGE, "tpm": None, "unlock_key": unlock}]}
    raw = base64.urlsafe_b64encode(json.dumps(says).encode()).decode().rstrip("=")
    return {"bytes": raw, "signatures": [{"key": k, "key_id": k[:16], "signature": "s"} for k in signers]}


def test_the_change_is_what_the_statement_signed():
    c = load().change(statement(), TARGETS, "Plant A", {}, "basic")
    assert c["action"] == "enrol_edge" and c["edge_id"] == "plant-a" and c["officer"].startswith("op:")
    assert (c["officer_key"], c["enrolment_key"], c["unlock_key"]) == (OFFICER, EDGE, UNLOCK)
    assert c["targets"] == [{"target": "plc-ssh", "role": "plc-operators", "entitlement": "plc-ssh"}]
    assert c["statement"] == statement()


def test_a_named_entitlement_and_no_unlock_key():
    c = load().change(statement(unlock=None), TARGETS, "Plant A", {"plc-ssh": "plant-ssh"}, "basic")
    assert c["targets"][0]["entitlement"] == "plant-ssh" and "unlock_key" not in c


@pytest.mark.parametrize("st,why", [
    (statement(officer="carol"), "not an anchor"),
    (statement(signers=(OFFICER,)), "the edge has not signed it"),
    (statement(signers=(EDGE,)), "the officer has not signed it"),
], ids=["username officer", "no edge signature", "no officer signature"])
def test_a_statement_the_desk_would_refuse_is_refused(st, why):
    with pytest.raises(SystemExit) as e:
        load().change(st, TARGETS, "Plant A", {}, "basic")
    assert why in str(e.value) and "nothing written" in str(e.value)

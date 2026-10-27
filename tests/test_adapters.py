# SPDX-License-Identifier: EUPL-1.2
"""The clerk adapter emits an offline-verifiable EDI and its residue measurement holds (decisions 0016/0017)."""
import importlib.util
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MID = pathlib.Path(__file__).resolve().parent.parent / "adapters" / "clerk" / "midpoint.py"


def _load(p):
    spec = importlib.util.spec_from_file_location(p.stem, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_clerk_adapter_emits_offline_verifiable_edi():
    assert _load(MID).main() == 0  # the emitted EDI verifies offline against the pinned key


def test_midpoint_gives_only_the_decisions():
    m = _load(MID)
    grants = m.read_grants(m.MIDPOINT_USER)
    assert len(grants) == 1
    g = grants[0]
    assert g["subject"] and g["target"] and g["not_before"] and g["not_after"]  # the native 1 of 6


def test_tampering_breaks_the_signature():
    m = _load(MID)
    k = Ed25519PrivateKey.generate()
    edi = m.emit_edi(m.read_grants(m.MIDPOINT_USER), edge_id="edge-001",
                     ceiling={"targets": ["00000000-0000-0000-0000-000000000008"]},
                     serial=1, horizons={}, signing_key=k)
    edi["body"]["serial"] = 999  # tamper after signing
    problems = m.verify_edi(edi, k.public_key(), edge_id="edge-001", last_serial=0,
                            ceiling_targets={"00000000-0000-0000-0000-000000000008"})
    assert any("signature" in p for p in problems)

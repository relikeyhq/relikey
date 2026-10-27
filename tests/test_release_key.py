# SPDX-License-Identifier: EUPL-1.2
"""The release key tool (decision 0027): its parsers fuzzed, and create run against a stand-in Bitwarden CLI."""
import base64
import json
import os
import struct
import sys

import pytest
from hypothesis import given, settings, strategies as st

import tools.release_key as rk

# RELIKEY_FUZZ_EXAMPLES runs the fuzzers longer (CI fuzz job, or locally); 400 each in the ordinary suite.
FUZZ = settings(max_examples=int(os.environ.get("RELIKEY_FUZZ_EXAMPLES", "400")), deadline=None)


def _blob(raw32: bytes) -> bytes:
    return struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + raw32


# --- fuzzed: every parser takes arbitrary input, answers or raises ValueError, never anything else -----------------

@FUZZ
@given(st.text())
def test_principal_accepts_only_its_alphabet(s):
    try:
        rk.validate_principal(s)
    except ValueError:
        return
    assert s and len(s) <= 63 and s[0] != "-" and set(s) <= set("abcdefghijklmnopqrstuvwxyz0123456789-")


@FUZZ
@given(st.text())
def test_item_name_never_carries_a_shell_or_cmd_character(s):
    try:
        rk.validate_item_name(s)
    except ValueError:
        return
    assert not set(s) & set(" \t\r\n\"'&|<>^%!()`$;,\\/*?")


@FUZZ
@given(st.text())
def test_public_key_parser_on_arbitrary_text(s):
    try:
        blob = rk.parse_public_key(s)
    except ValueError:
        return
    assert len(blob) == 51 and blob.startswith(_blob(b"\0" * 32)[:19])


@FUZZ
@given(st.binary(min_size=32, max_size=32), st.text(alphabet=" \t", max_size=3), st.text(max_size=20))
def test_a_real_key_line_round_trips(raw, pad, comment):
    blob = _blob(raw)
    line = f"{pad}ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"
    if comment.strip() and comment.split() and len(line.split()) >= 2:
        assert rk.parse_public_key(line) == blob


@FUZZ
@given(st.binary(max_size=80))
def test_a_wrong_blob_is_refused(blob):
    if len(blob) == 51 and blob[:19] == _blob(b"\0" * 32)[:19]:
        return
    with pytest.raises(ValueError):
        rk.parse_public_key("ssh-ed25519 " + base64.b64encode(blob).decode())


@FUZZ
@given(st.text())
def test_bw_listing_parser_on_arbitrary_text(s):
    try:
        assert isinstance(rk.find_items(s, "relikey-releases"), list)
    except ValueError:
        pass


_items = st.lists(st.fixed_dictionaries({"name": st.text(max_size=20), "id": st.text(max_size=8)}), max_size=8)


@FUZZ
@given(_items, st.text(min_size=1, max_size=20))
def test_bw_listing_returns_exact_name_matches_only(items, name):
    assert rk.find_items(json.dumps(items), name) == [i["id"] for i in items if i["name"] == name]


@FUZZ
@given(st.text(max_size=200), st.text(min_size=1, max_size=60), st.binary(min_size=32, max_size=32))
def test_the_stored_item_reads_back_only_as_written(pem, passphrase, raw):
    item = rk.item_json("relikey-releases", pem, passphrase, _blob(raw))
    stored = json.dumps(item)
    assert rk.stored_matches(stored, pem, passphrase)
    assert not rk.stored_matches(stored, pem + "x", passphrase)
    assert not rk.stored_matches(stored, pem, passphrase + "x")
    item["fields"].append({"name": "passphrase", "value": passphrase, "type": 1})
    assert not rk.stored_matches(json.dumps(item), pem, passphrase)  # two passphrases: ambiguous, refused


@FUZZ
@given(st.text())
def test_stored_matches_on_arbitrary_text(s):
    assert rk.stored_matches(s, "pem", "pass") in (True, False)


@FUZZ
@given(st.binary(min_size=32, max_size=32))
def test_the_signers_file_has_one_key_line(raw):
    text = rk.signers_file("relikey-releases", _blob(raw), "2026-10-27")
    keys = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    assert keys == [rk.signers_line("relikey-releases", _blob(raw))]


# --- create, against a stand-in bw -----------------------------------------------------------------------------------

FAKE_BW = r'''
import base64, json, os, sys
state = os.environ["FAKE_BW_STATE"]
items = json.load(open(state)) if os.path.exists(state) else []
cmd = sys.argv[1]
if os.environ.get("FAKE_BW_FAIL") == cmd:
    sys.stderr.write("simulated failure\n"); sys.exit(1)
if cmd in ("sync", "lock"):
    pass
elif cmd == "unlock":
    print("session-from-unlock")
elif cmd == "list":
    print(json.dumps([{"name": i["name"], "id": i["id"]} for i in items]))
elif cmd == "create":
    if sys.argv[2:] != ["item"]:
        sys.exit(3)  # nothing secret may arrive as an argument
    item = json.loads(base64.b64decode(sys.stdin.read()))
    item["id"] = "id-%d" % len(items)
    items.append(item)
    json.dump(items, open(state, "w"))
    print(json.dumps({"id": item["id"]}))
elif cmd == "get":
    item = next(i for i in items if i["id"] == sys.argv[3])
    if os.environ.get("FAKE_BW_CORRUPT"):
        item = dict(item, notes=item["notes"][:-2])
    print(json.dumps(item))
'''


@pytest.fixture
def bw(tmp_path, monkeypatch):
    script = tmp_path / "fake_bw.py"
    script.write_text(FAKE_BW, encoding="utf-8")
    state = tmp_path / "bw.json"
    monkeypatch.setenv("RELIKEY_BW", json.dumps([sys.executable, str(script)]))
    monkeypatch.setenv("FAKE_BW_STATE", str(state))
    monkeypatch.setenv("BW_SESSION", "test")
    monkeypatch.delenv("FAKE_BW_FAIL", raising=False)
    monkeypatch.delenv("FAKE_BW_CORRUPT", raising=False)
    return state


def _paths(tmp_path):
    (tmp_path / "ssh").mkdir(exist_ok=True)
    return tmp_path / "ssh" / "relikey-releases", tmp_path / "relikey.allowed_signers"


def test_create_stores_first_then_writes_a_key_that_opens_with_the_stored_passphrase(tmp_path, bw):
    pytest.importorskip("bcrypt")
    from cryptography.hazmat.primitives.serialization import load_ssh_private_key

    key, signers = _paths(tmp_path)
    fp = rk.create(key, "relikey-releases", "relikey-releases", signers, "2026-10-27")
    (item,) = json.loads(bw.read_text())
    passphrase = next(f["value"] for f in item["fields"] if f["name"] == "passphrase")
    assert key.read_text() == item["notes"]
    with pytest.raises((ValueError, TypeError)):
        load_ssh_private_key(key.read_bytes(), password=None)  # encrypted at rest
    private = load_ssh_private_key(key.read_bytes(), password=passphrase.encode())
    blob = rk.parse_public_key(key.with_name(key.name + ".pub").read_text())
    from cryptography.hazmat.primitives import serialization
    pub = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    assert rk.parse_public_key(pub.decode()) == blob
    assert rk.fingerprint(blob) == fp
    assert rk.signers_line("relikey-releases", blob) in signers.read_text().splitlines()
    assert rk.status(key, signers, "relikey-releases") == 0


def test_create_refuses_an_existing_key_and_changes_nothing(tmp_path, bw):
    key, signers = _paths(tmp_path)
    key.write_text("old")
    with pytest.raises(rk.Refused):
        rk.create(key, "relikey-releases", "relikey-releases", signers, "2026-10-27")
    assert key.read_text() == "old" and not bw.exists() and not signers.exists()


def test_create_refuses_an_existing_item_before_making_a_key(tmp_path, bw):
    bw.write_text(json.dumps([{"name": "relikey-releases", "id": "x", "notes": "older key"}]))
    key, signers = _paths(tmp_path)
    with pytest.raises(rk.Refused):
        rk.create(key, "relikey-releases", "relikey-releases", signers, "2026-10-27")
    assert not key.exists() and not signers.exists() and len(json.loads(bw.read_text())) == 1


@pytest.mark.parametrize("fail", ["sync", "list", "create", "get"])
def test_a_bitwarden_failure_writes_no_key_file(tmp_path, bw, monkeypatch, fail):
    pytest.importorskip("bcrypt")
    monkeypatch.setenv("FAKE_BW_FAIL", fail)
    key, signers = _paths(tmp_path)
    with pytest.raises(rk.Refused):
        rk.create(key, "relikey-releases", "relikey-releases", signers, "2026-10-27")
    assert not key.exists() and not signers.exists()


def test_an_item_that_does_not_read_back_writes_no_key_file(tmp_path, bw, monkeypatch):
    pytest.importorskip("bcrypt")
    monkeypatch.setenv("FAKE_BW_CORRUPT", "1")
    key, signers = _paths(tmp_path)
    with pytest.raises(rk.Refused, match="does not read back"):
        rk.create(key, "relikey-releases", "relikey-releases", signers, "2026-10-27")
    assert not key.exists() and not signers.exists()


def test_nothing_secret_reaches_the_output(tmp_path, bw, capsys):
    pytest.importorskip("bcrypt")
    key, signers = _paths(tmp_path)
    assert rk.main(["create", "--key", str(key), "--signers", str(signers)]) == 0
    (item,) = json.loads(bw.read_text())
    passphrase = next(f["value"] for f in item["fields"] if f["name"] == "passphrase")
    out = capsys.readouterr()
    assert passphrase not in out.out + out.err and "PRIVATE KEY" not in out.out + out.err

# SPDX-License-Identifier: EUPL-1.2
"""The installers' helper calls fit their helpers: a keyword the helper does not take fails here, not on a lab box
(full-stack run 5: the edge installer called write(..., keep=False), which only the core installer's write takes).
Their refusals say why and what completes the task, and stop before anything is started."""
import ast
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "deploy").glob("*/*.py"))


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_local_helper_call_uses_its_parameters(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    defs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            a = node.args
            if a.kwarg is None:   # a **kwargs helper takes anything
                defs[node.name] = {x.arg for x in a.args + a.kwonlyargs + a.posonlyargs}
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in defs:
            for kw in node.keywords:
                if kw.arg is not None and kw.arg not in defs[node.func.id]:
                    bad.append(f"line {node.lineno}: {node.func.id}(..., {kw.arg}=...)")
    assert not bad, f"{path.name}: " + "; ".join(bad)


def installer(name: str, secrets: Path, monkeypatch):
    """deploy/<name>/install.py as a module, writing into secrets instead of deploy/secrets/."""
    spec = importlib.util.spec_from_file_location(f"{name}_install", ROOT / "deploy" / name / "install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "SECRETS", secrets)

    def started(*a, **kw):   # a refusal that no longer fires must not start containers on the test machine
        raise AssertionError(f"the installer went past its checks and ran {a[0] if a else kw}")
    monkeypatch.setattr(mod.subprocess, "run", started)
    monkeypatch.setattr(mod.subprocess, "Popen", started)
    return mod


CORE = ["--broker-host", "id.example", "--desk-host", "desk.example", "--edge-host", "edge.example",
        "--root", "Root Holder <root@example>", "--officer", "Officer Name <officer@example>"]
EDGE = ["--edge", "plant-a", "--desk", "https://edge.example", "--desk-pin", "a" * 64, "--bundle-key", "b" * 64,
        "--officer-key", "c" * 64]


def swap(args: list[str], flag: str, value: str) -> list[str]:
    i = args.index(flag)
    return args[:i + 1] + [value] + args[i + 2:]


# Each refusal an operator can meet before anything starts: what went wrong (why) and what completes the task (next).
# A message without its next step leaves an operator at a site with no developer at hand stuck (issue 22).
REFUSALS = [
    ("core", swap(CORE, "--desk-host", "id.example"), "each needs a DNS name of its own", "give three different"),
    ("core", CORE + ["--realm", "master"], "the broker's own administration realm", "leave it out"),
    ("core", swap(CORE, "--root", "root@example"), "no name and e-mail address found", "\"First Last <e-mail>\""),
    ("core", swap(CORE, "--officer", "Someone Else <root@example>"), "root@example given more than once",
     "Give each role a person of its own"),
    ("core", CORE + ["--keyclerk-ref", "main"], "for a lab only", "it needs --lab and --keyclerk-src"),
    ("edge", swap(EDGE, "--bundle-key", "B" * 64), "not 64 lower-case hex characters", "the desk's bundle key"),
    ("edge", swap(EDGE, "--officer-key", "c" * 63), "the agent would refuse to start", "the edge officer's public key"),
    ("edge", [a for a in EDGE if a not in ("--desk-pin", "a" * 64)], "the agent checks the desk by one of them",
     "The core's install.py printed both"),
    ("edge", EDGE + ["--sso-issuer", "http://id.example/realms/relikey", "--sso-secret-file", "s"], "https only",
     "give https://<broker>/realms/<realm>"),
    ("edge", EDGE + ["--sso-issuer", "https://id.example/realms/relikey"], "go together",
     "from the core's add_edge.py"),
    ("edge", EDGE + ["--sso-issuer", "https://id.example/realms/relikey", "--sso-secret-file", "s"],
     "needs --warpgate-url", "give the same one here"),
]


@pytest.mark.parametrize("which,args,why,nxt", REFUSALS, ids=[f"{w}: {why}" for w, _, why, _ in REFUSALS])
def test_a_refusal_says_why_and_what_to_do_next(which, args, why, nxt, tmp_path, monkeypatch):
    mod = installer(which, tmp_path / "secrets", monkeypatch)
    monkeypatch.setattr(sys, "argv", ["install.py"] + args)
    with pytest.raises(SystemExit) as refused:
        mod.main()
    message = str(refused.value.code)
    assert why in message and nxt in message, message


@pytest.mark.parametrize("where", ["keys/enrolment.key", "enrolment.key"], ids=["key directory", "before #134"])
def test_an_installed_edge_is_not_re_keyed_in_passing(where, tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    (secrets / where).parent.mkdir(parents=True)
    (secrets / where).write_text("d" * 64, encoding="utf-8")
    mod = installer("edge", secrets, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["install.py"] + EDGE)
    with pytest.raises(SystemExit) as refused:
        mod.main()
    message = str(refused.value.code)
    assert "the desk would refuse the edge until an officer enrols it again" in message and "--re-key" in message
    assert (secrets / where).read_text(encoding="utf-8") == "d" * 64


# #134: the pod mounts a writable key directory, where a rotation can rename; the agent's configuration points there.
def test_the_pod_keeps_the_enrolment_key_in_a_writable_directory():
    compose = (ROOT / "deploy" / "edge" / "compose.yaml").read_text(encoding="utf-8")
    assert "../secrets/keys:/etc/relikey/keys " in compose, "the key directory is mounted writable (no :ro)"
    assert "enrolment.key:/etc/relikey" not in compose, "the key is never a single-file mount: nothing renames over it"
    src = (ROOT / "deploy" / "edge" / "install.py").read_text(encoding="utf-8")
    assert '"enrolment_key_file": "/etc/relikey/" + KEY' in src


def legacy_edge(secrets: Path, cfg: dict) -> None:
    import json
    secrets.mkdir()
    (secrets / "enrolment.key").write_text("d" * 64 + "\n", encoding="utf-8")
    (secrets / "agent.json").write_text(json.dumps(cfg), encoding="utf-8")


def test_move_keys_moves_an_older_installs_key_and_points_the_agent_there(tmp_path, monkeypatch):
    import json
    secrets = tmp_path / "secrets"
    legacy_edge(secrets, {"edge": "plant-a", "enrolment_key_file": "/etc/relikey/enrolment.key"})
    mod = installer("edge", secrets, monkeypatch)
    monkeypatch.setattr(mod, "fix_owners", lambda engine: None)
    assert mod.move_keys_main([]) == 0
    assert not (secrets / "enrolment.key").exists()
    assert (secrets / "keys" / "enrolment.key").read_text(encoding="utf-8") == "d" * 64 + "\n"
    cfg = json.loads((secrets / "agent.json").read_text(encoding="utf-8"))
    assert cfg == {"edge": "plant-a", "enrolment_key_file": "/etc/relikey/keys/enrolment.key"}
    assert mod.move_keys_main([]) == 0, "a second run finds the key moved and does nothing"
    assert not list(secrets.glob("*.tmp")), "agent.json is replaced whole, no temporary file left"


@pytest.mark.parametrize("setup,why,nxt", [
    (lambda s: (s / "keys").mkdir() or (s / "keys" / "enrolment.key").write_text("e" * 64), "both", "keep the one the desk knows"),
    (lambda s: (s / "agent.json").write_text('{"next_enrolment_key_file": "/etc/relikey/n.key", '
                                             '"rotation_statement_file": "/etc/relikey/r.json"}'),
     "stages a rotation", "remove both settings first"),
], ids=["two keys", "a staged rotation"])
def test_move_keys_refuses_what_it_cannot_settle(setup, why, nxt, tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    legacy_edge(secrets, {"edge": "plant-a", "enrolment_key_file": "/etc/relikey/enrolment.key"})
    setup(secrets)
    mod = installer("edge", secrets, monkeypatch)
    with pytest.raises(SystemExit) as refused:
        mod.move_keys_main([])
    message = str(refused.value.code)
    assert why in message and nxt in message, message
    assert (secrets / "enrolment.key").exists(), "nothing moved"


# KeyClerk 0.29.0: the signer pins the reconciler's identity-map key, the public half of mark.key.
def test_the_identity_key_is_the_public_half_of_the_mark_key(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    k = Ed25519PrivateKey.generate()
    (secrets / "mark.key").write_text(k.private_bytes_raw().hex() + "\n", encoding="utf-8")
    mod = installer("core", secrets, monkeypatch)
    mod.write_identity_key()
    want = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    assert (secrets / "identity.pub").read_text(encoding="utf-8") == want + "\n"
    (secrets / "mark.key").write_text("not hex\n", encoding="utf-8")
    with pytest.raises(SystemExit) as refused:
        mod.write_identity_key()
    assert "restore it from the core's backup" in str(refused.value.code)


def test_the_signer_pins_the_identity_key():
    compose = (ROOT / "deploy" / "core" / "compose.yaml").read_text(encoding="utf-8")
    assert '"--identity-key", "/run/secrets/identity.pub"' in compose
    assert "../secrets/identity.pub:/run/secrets/identity.pub:ro" in compose


def test_upgrade_029_moves_the_bundle_key_into_the_signer_then_starts_in_order(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "mark.key").write_text("11" * 32 + "\n", encoding="utf-8")
    mod = installer("core", secrets, monkeypatch)
    calls = []

    class Done:
        returncode = 0

    def run(cmd, **kw):
        calls.append(cmd)
        return Done()
    monkeypatch.setattr(mod.subprocess, "run", run)
    monkeypatch.setattr(mod, "fix_owners", lambda engine: None)
    assert mod.upgrade_029_main([]) == 0
    flat = [" ".join(c) for c in calls]
    assert any("stop desk" in c for c in flat), "the desk stops first: it refuses edges while it holds a bundle.key"
    imp = next(i for i, c in enumerate(flat) if "import-bundle-key" in c)
    rm = next(i for i, c in enumerate(flat) if c.endswith("rm /s/bundle.key"))
    assert imp < rm, "the desk's copy goes only after the signer took it"
    ups = [c.split()[-1] for c in flat if "up -d --force-recreate" in c]
    assert ups == ["reconcile", "signer", "desk"], "KeyClerk 0.29.0's order: the map, its pin, then the desk"
    assert (secrets / "identity.pub").exists()


def test_upgrade_029_refuses_a_core_without_a_mark_key(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    mod = installer("core", secrets, monkeypatch)
    with pytest.raises(SystemExit) as refused:
        mod.upgrade_029_main([])
    message = str(refused.value.code)
    assert "predates KeyClerk 0.27.0" in message and "then this" in message

# SPDX-License-Identifier: EUPL-1.2
"""The installers' helper calls fit their helpers: a keyword the helper does not take fails here, not on a lab box
(full-stack run 5: the edge installer called write(..., keep=False), which only the core installer's write takes).
Their refusals say why and what completes the task, and stop before anything is started."""
import ast
import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

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


# Walk 2026-11-06, F15: core and edge installed from one checkout share deploy/secrets/, and the edge's front.crt
# replaced the core's. Each installer refuses the other's directory before writing anything.
@pytest.mark.parametrize("which,args,other,nxt", [
    ("core", CORE, "agent.json", "Install the core from its own checkout"),
    ("edge", EDGE, "core.env", "copy into its deploy/secrets/ only what the core gave it")], ids=["core", "edge"])
def test_an_installer_refuses_the_other_components_secrets(which, args, other, nxt, tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / other).write_text("x", encoding="utf-8")
    mod = installer(which, secrets, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["install.py"] + args)
    with pytest.raises(SystemExit) as refused:
        mod.main()
    message = str(refused.value.code)
    assert other in message and "Nothing was written" in message and nxt in message, message
    assert sorted(p.name for p in secrets.iterdir()) == [other]


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


# Decision 0028: the cold spare shows people what the active node shows (its SSH host key, the front's certificate).
OPENSSH_PEM = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"   # assembled: the literal reads as a key to the leak scan


def test_the_site_host_key_is_an_openssh_ed25519_key_with_its_fingerprint(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.serialization import load_ssh_private_key
    mod = installer("edge", tmp_path / "secrets", monkeypatch)
    pem, fp = mod.site_host_key()
    assert pem.startswith(OPENSSH_PEM)
    assert load_ssh_private_key(pem.encode(), password=None) is not None
    assert fp.startswith("SHA256:") and len(fp) == 50 and "=" not in fp
    assert mod.site_host_key()[0] != pem, "a new key each time"


def test_warpgate_reads_the_site_key_from_its_keys_path(tmp_path, monkeypatch):
    mod = installer("edge", tmp_path / "secrets", monkeypatch)
    assert mod.with_site_keys({"ssh": {"enable": True}}) == {"ssh": {"enable": True, "keys": "/data/keys"}}
    assert mod.with_site_keys({}) == {"ssh": {"keys": "/data/keys"}}


def test_site_keys_out_makes_the_set_from_an_installed_node(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "front.crt").write_text("CERT\n", encoding="utf-8")
    (secrets / "front.key").write_text("KEY\n", encoding="utf-8")
    mod = installer("edge", secrets, monkeypatch)
    out = tmp_path / "site"
    assert mod.site_keys_main(["--out", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == sorted(mod.SITE_FILES)
    assert (out / "site.crt").read_text(encoding="utf-8") == "CERT\n"
    assert (out / "site.key").read_text(encoding="utf-8") == "KEY\n"
    assert (out / "host-ed25519").read_text(encoding="utf-8").startswith(OPENSSH_PEM)
    with pytest.raises(SystemExit) as refused:   # never into an existing directory: no older set mixed in
        mod.site_keys_main(["--out", str(out)])
    assert "exists" in str(refused.value.code) and "new directory" in str(refused.value.code)


@pytest.mark.parametrize("args,why,nxt", [
    (["site-keys", "--out", "{tmp}/site"], "no front certificate and key", "run this on an installed node"),
    (["site-keys", "--apply", "{tmp}/empty"], "missing", "site-keys --out DIR"),
    (EDGE + ["--site-keys", "{tmp}/empty"], "missing", "carry DIR here whole"),
], ids=["out on a node not installed", "apply an incomplete set", "install with an incomplete set"])
def test_site_keys_refusals_say_why_and_what_to_do_next(args, why, nxt, tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir()
    mod = installer("edge", tmp_path / "secrets", monkeypatch)
    monkeypatch.setattr(sys, "argv", ["install.py"] + [a.replace("{tmp}", str(tmp_path)) for a in args])
    with pytest.raises(SystemExit) as refused:
        mod.main()
    message = str(refused.value.code)
    assert why in message and nxt in message, message


class _Ran:
    """Records the commands an installer runs, answering `volume exists` with no and `inspect` with a path."""
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, *a, **kw):
        import subprocess as sp
        self.calls.append(list(cmd))
        if cmd[1:3] == ["volume", "exists"]:
            return sp.CompletedProcess(cmd, 1, "", "")
        if cmd[1:3] == ["volume", "inspect"]:
            return sp.CompletedProcess(cmd, 0, "/vol/relikey-edge_agent/_data\n", "")
        return sp.CompletedProcess(cmd, 0, "", "")


def test_rootless_podman_sets_the_core_owners(tmp_path, monkeypatch):
    """F3 of the fresh-install walk of v0.3.0-rc.2: the installer only printed a note and KeyClerk's setup then failed
    reading its secret. Under rootless podman it sets the owners through `podman unshare`, as the docker branch does."""
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    for f in ("keyclerk-writer.secret", "records.key", "people.json", "front.crt", "front.key"):
        (secrets / f).write_text("x", encoding="utf-8")
    mod = installer("core", secrets, monkeypatch)
    ran = _Ran()
    monkeypatch.setattr(mod.subprocess, "run", ran)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1001, raising=False)
    mod.fix_owners("podman")
    assert len(ran.calls) == 1 and ran.calls[0][:3] == ["podman", "unshare", "sh"]
    script = ran.calls[0][-1]
    assert f"chown 10001:10001 '{secrets / 'keyclerk-writer.secret'}' && chmod 600" in script
    assert f"chown 10001:0 '{secrets / 'people.json'}' && chmod 640" in script
    assert f"chown 0:0 '{secrets / 'front.key'}' && chmod 640" in script


def test_a_rerun_after_the_first_sign_ins_does_not_chown_a_deleted_people_file(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    for f in ("records.key", "front.crt", "front.key"):
        (secrets / f).write_text("x", encoding="utf-8")
    mod = installer("core", secrets, monkeypatch)
    for engine in ("podman", "docker"):
        ran = _Ran()
        monkeypatch.setattr(mod.subprocess, "run", ran)
        monkeypatch.setattr(mod.os, "geteuid", lambda: 1001, raising=False)
        monkeypatch.setattr(mod.os, "getgid", lambda: 1001, raising=False)
        mod.fix_owners(engine)
        assert "people.json" not in ran.calls[0][-1], engine


def test_rootless_podman_sets_the_edge_owners_and_the_state_volume(tmp_path, monkeypatch):
    """F11 and F13: the agent's files and its state volume, the agent's and 0700, before compose first mounts them;
    the volume carries compose's own labels."""
    secrets = tmp_path / "secrets"
    (secrets / "keys").mkdir(parents=True)
    for f in ("agent.json", "warpgate.token", "front.key", "keys/enrolment.key"):
        (secrets / f).write_text("x", encoding="utf-8")
    mod = installer("edge", secrets, monkeypatch)
    ran = _Ran()
    monkeypatch.setattr(mod.subprocess, "run", ran)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1001, raising=False)
    mod.fix_owners("podman")
    owners = ran.calls[0][-1]
    assert ran.calls[0][:2] == ["podman", "unshare"]
    for f in ("agent.json", "warpgate.token", "keys"):
        assert f"chown -R 65532:65532 '{secrets / f}'" in owners
    assert f"chown 0:0 '{secrets / 'front.key'}' && chmod 600" in owners
    create = next(c for c in ran.calls if c[1:3] == ["volume", "create"])
    assert "com.docker.compose.project=relikey-edge" in create and "com.docker.compose.volume=agent" in create
    assert create[-1] == "relikey-edge_agent"
    assert ran.calls[-1][:2] == ["podman", "unshare"]
    assert ran.calls[-1][-1] == "chown 65532:65532 '/vol/relikey-edge_agent/_data' && chmod 0700 '/vol/relikey-edge_agent/_data'"


def test_the_state_volume_name_is_the_one_compose_makes():
    compose = yaml.safe_load((ROOT / "deploy" / "edge" / "compose.yaml").read_text(encoding="utf-8"))
    assert compose["name"] == "relikey-edge" and "agent" in compose["volumes"]
    assert any(str(v).startswith("agent:/var/lib/relikey") for v in compose["services"]["agent"]["volumes"])


def test_rootless_podman_sets_the_fleet_page_secret():
    src = (ROOT / "deploy" / "core" / "fleet_page.py").read_text(encoding="utf-8")
    assert '[o.engine, "unshare", "sh", "-c", f"chown {FLEET_UID}:{FLEET_UID}' in src


def test_the_agent_gets_the_desk_ca_the_installer_writes():
    """--desk-ca, the guide's route for a local CA: install.py points the agent at /etc/relikey/desk-ca.pem and writes
    deploy/secrets/desk-ca.pem, so the pod mounts it (fresh-install walk of v0.3.0-rc.2, F12: it was never mounted and
    the agent restart-looped). An edge installed with a pin before this gets an empty directory, which it never reads."""
    compose = yaml.safe_load((ROOT / "deploy" / "edge" / "compose.yaml").read_text(encoding="utf-8"))
    mounts = [v for v in compose["services"]["agent"]["volumes"] if isinstance(v, dict)]
    ca = [v for v in mounts if v["target"] == "/etc/relikey/desk-ca.pem"]
    assert ca and ca[0]["source"] == "../secrets/desk-ca.pem" and ca[0]["read_only"] is True
    assert ca[0]["bind"]["create_host_path"] is True
    install = (ROOT / "deploy" / "edge" / "install.py").read_text(encoding="utf-8")
    assert '"/etc/relikey/desk-ca.pem"' in install and 'write("desk-ca.pem"' in install


def test_every_file_mounted_into_the_agent_is_one_it_can_read(tmp_path, monkeypatch):
    """The agent runs as 65532 under every engine and owner mode. A file compose mounts into it is either one the
    installer gives the agent (AGENT_READS, chowned by fix_owners or podman unshare) or a public one written 0644
    (AGENT_PUBLIC). rc.3 walk R3 (#164): desk-ca.pem was mounted, written 0600 by the installing user, and in neither
    list, so the agent could not read it on rootless podman."""
    mod = installer("edge", tmp_path / "secrets", monkeypatch)
    compose = yaml.safe_load((ROOT / "deploy" / "edge" / "compose.yaml").read_text(encoding="utf-8"))
    sources = []
    for v in compose["services"]["agent"]["volumes"]:
        src = v["source"] if isinstance(v, dict) else v.split(":")[0]
        if src.startswith("../secrets/"):
            sources.append(src.removeprefix("../secrets/"))
    known = set(mod.AGENT_READS) | set(mod.AGENT_PUBLIC)
    assert sources and not [s for s in sources if s not in known], f"mounted but in neither list: {sources}"
    # the public ones are written world-readable, without an owner that rootless podman cannot give
    tree = ast.parse((ROOT / "deploy" / "edge" / "install.py").read_text(encoding="utf-8"))
    public_writes = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "chmod"
                and isinstance(node.func.value, ast.Call) and getattr(node.func.value.func, "id", "") == "write"):
            inner = node.func.value
            name = inner.args[0].value if inner.args and isinstance(inner.args[0], ast.Constant) else None
            owner_none = any(k.arg == "owner" and isinstance(k.value, ast.Constant) and k.value.value is None
                             for k in inner.keywords)
            public_writes[name] = (node.args[0].value, owner_none)
    assert public_writes.get("desk-ca.pem") == (0o644, True), public_writes


def test_the_core_publishes_the_port_the_installer_names():
    """--port reaches the published port, not only the URLs (fresh-install walk of v0.3.0-rc.2, F2): rootless podman
    cannot bind 443, and the guide's advice is a higher --port."""
    compose = (ROOT / "deploy" / "core" / "compose.yaml").read_text(encoding="utf-8")
    assert '"${FRONT_PORT:-443}:8443"' in compose and '"443:8443"' not in compose
    install = (ROOT / "deploy" / "core" / "install.py").read_text(encoding="utf-8")
    assert "FRONT_PORT={port}" in install


def test_the_sign_in_button_names_the_broker(tmp_path, monkeypatch):
    """rc.4 walk W11 (#176): beside Warpgate's own username and password form, which no ReliKey person uses, a bare
    "Sign in" did not say it is the organisation's sign-in. The button names the broker, or the site's own words."""
    mod = installer("edge", tmp_path / "secrets", monkeypatch)
    assert mod.sso_label(None, "https://id.example.org:8443/realms/relikey") == "Sign in with id.example.org"
    assert mod.sso_label("  Sign in with Plant A's account ", "https://id.example.org") == "Sign in with Plant A's account"
    src = (ROOT / "deploy" / "edge" / "install.py").read_text(encoding="utf-8")
    assert '"label": label' in src and '"label": "Sign in"' not in src

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


def test_an_installed_edge_is_not_re_keyed_in_passing(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "enrolment.key").write_text("d" * 64, encoding="utf-8")
    mod = installer("edge", secrets, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["install.py"] + EDGE)
    with pytest.raises(SystemExit) as refused:
        mod.main()
    message = str(refused.value.code)
    assert "the desk would refuse the edge until an officer enrols it again" in message and "--re-key" in message
    assert (secrets / "enrolment.key").read_text(encoding="utf-8") == "d" * 64

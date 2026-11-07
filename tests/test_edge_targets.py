# SPDX-License-Identifier: EUPL-1.2
"""deploy/edge/targets.py checks the targets file on the host and hands it to the agent's `targets` command inside the
pod, where Warpgate's loopback admin API is (walk 2026-11-06, F14). The token and the pin stay with the agent, whose
pinned client is tested in agent/internal/httpx (TestThePinStillHoldsOnAHybridLink); applying is tested in
agent/internal/warpgate (targets_test.go)."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

PLC = {"name": "plc-ssh", "role": "plc-operators", "ssh": {"host": "10.0.0.5", "username": "plcuser"},
       "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlcHostKey"}


def load_targets():
    spec = importlib.util.spec_from_file_location("edge_targets", ROOT / "deploy" / "edge" / "targets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def edge(tmp_path, monkeypatch):
    mod = load_targets()
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "GOVERNED", tmp_path / "governed-roles.json")
    calls = []
    answer = {"code": 0}

    def run(cmd, input=None, text=None):
        calls.append((cmd, json.loads(input)))
        return subprocess.CompletedProcess(cmd, answer["code"])

    monkeypatch.setattr(mod.subprocess, "run", run)
    return mod, tmp_path, calls, answer


def apply(mod, tmp, monkeypatch, spec, *extra):
    f = tmp / "targets.yaml"
    f.write_text(json.dumps(spec), encoding="utf-8")   # JSON is YAML
    monkeypatch.setattr(sys, "argv", ["targets.py", str(f), *extra])
    return mod.main()


def test_the_targets_go_to_the_agent_in_the_pod(edge, monkeypatch):
    mod, tmp, calls, _ = edge
    assert apply(mod, tmp, monkeypatch, {"targets": [PLC]}, "--engine", "docker") == 0
    (cmd, sent), = calls
    assert cmd[:2] == ["docker", "compose"]
    assert cmd[cmd.index("exec"):] == ["exec", "-T", "agent", "/relikey-agent", "targets", "-in", "-"]
    assert sent == {"targets": [{**PLC, "ssh": {**PLC["ssh"], "port": 22}}]}
    governed = json.loads((tmp / "governed-roles.json").read_text(encoding="utf-8"))
    assert [r["displayName"] for r in governed["Resources"]] == ["plc-operators"]


def test_a_target_without_host_key_is_refused_before_the_pod(edge, monkeypatch):
    mod, tmp, calls, _ = edge
    with pytest.raises(SystemExit) as e:
        apply(mod, tmp, monkeypatch, {"targets": [{k: v for k, v in PLC.items() if k != "host_key"}]})
    assert "host_key is missing" in str(e.value) and "nothing changed" in str(e.value)
    assert calls == [] and not (tmp / "governed-roles.json").exists()


def test_an_agent_refusal_leaves_the_governed_roles(edge, monkeypatch):
    mod, tmp, calls, answer = edge
    answer["code"] = 1
    with pytest.raises(SystemExit) as e:
        apply(mod, tmp, monkeypatch, {"targets": [PLC]})
    assert "did not apply" in str(e.value) and "up -d" in str(e.value)
    assert len(calls) == 1 and not (tmp / "governed-roles.json").exists()

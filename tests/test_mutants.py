# SPDX-License-Identifier: EUPL-1.2
"""agent/mutants.py picks the mutants a change can affect (--changed) and splits them into parts (--shard): a pull
request runs only what it can affect; a changed test runs every mutant of its package, a changed shared test helper or
the harness every mutant."""
import argparse
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("agent_mutants", ROOT / "agent" / "mutants.py")
mutants = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mutants)
ALL = mutants.MUTANTS


def test_every_mutated_file_maps_to_a_file_in_the_repository():
    # a wrong mapping would make --changed select nothing for a change to that file
    for _, path, _, _ in ALL:
        assert (ROOT / mutants.repo_path(path)).is_file(), mutants.repo_path(path)
    assert {mutants.repo_path(p).split("/")[0] for _, p, _, _ in ALL} == {"agent", "fleet"}


def test_main_runs_each_mutant_against_its_own_package_only():
    # the package-scoped selection rests on this: a mutant is killed or not by `go test ./<its package>/` alone
    src = (ROOT / "agent" / "mutants.py").read_text(encoding="utf-8")
    assert src.count('"go", "test"') == 1
    assert '["go", "test", "-count=1", "./" + str(pkg).replace("\\\\", "/") + "/"]' in src


@pytest.mark.parametrize("changed", [
    "agent/internal/fakes/fakewg.go",              # fakes and test helpers shared by packages
    "agent/internal/testemit/emit.go",
    "fleet/internal/registry/regtest/passkey.go",
    "agent/mutants.py",                            # the harness itself
    "agent/build.py",
    "agent/go.mod",
    "fleet/go.sum",
])
def test_a_shared_test_or_harness_change_runs_every_mutant(changed):
    picked, why = mutants.select_changed(ALL, ["README.md", changed])
    assert picked == ALL
    assert changed in why


def _in_package(pkg):
    return [m for m in ALL if mutants.repo_path(m[1]).rsplit("/", 1)[0] == pkg]


@pytest.mark.parametrize("changed, pkg", [
    ("agent/internal/kcedge/kcedge_test.go", "agent/internal/kcedge"),       # a weakened test
    ("fleet/internal/page/page_test.go", "fleet/internal/page"),
    ("agent/internal/kcedge/testdata/edge.json", "agent/internal/kcedge"),   # test data
    ("fleet/internal/page/testdata/browser_ceremony.py", "fleet/internal/page"),
    ("brand/mark/geometry.json", "agent/internal/agent"),                    # read by a test from outside
])
def test_a_test_change_runs_every_mutant_of_its_package(changed, pkg):
    picked, why = mutants.select_changed(ALL, [changed, "docs/agent.md"])
    assert picked == _in_package(pkg)
    assert 0 < len(picked) < len(ALL)
    assert "the tests of 1 package" in why


def test_a_package_read_by_another_package_s_tests_runs_both():
    # seam_test.go in apply reads the agent package's sources
    picked, _ = mutants.select_changed(ALL, ["agent/internal/agent/agent_test.go"])
    assert picked == [m for m in ALL if m in _in_package("agent/internal/agent") or m in _in_package(
        "agent/internal/apply")]


def test_every_test_input_from_outside_its_package_is_listed():
    # a test reading "..": a change there must select the reading package's mutants (mutants.TEST_INPUTS)
    readers = set()
    for module in ("agent", "fleet"):
        for f in (ROOT / module).rglob("*_test.go"):
            src = f.read_text(encoding="utf-8")
            if '"..",' in src or '"../' in src:
                readers.add(f.parent.relative_to(ROOT).as_posix())
    assert readers and readers <= set(mutants.TEST_INPUTS), readers - set(mutants.TEST_INPUTS)


def test_a_change_to_a_mutated_file_runs_its_mutants_only():
    target = next(mutants.repo_path(p) for _, p, _, _ in ALL if "kcedge" in p.parts)
    picked, why = mutants.select_changed(ALL, [target, "docs/agent.md"])
    assert picked == [m for m in ALL if mutants.repo_path(m[1]) == target]
    assert 0 < len(picked) < len(ALL)
    assert "1 mutated file(s) and the tests of 0 package" in why


def test_a_fleet_file_is_matched_by_its_repository_path():
    picked, _ = mutants.select_changed(ALL, ["fleet/internal/admin/admin.go"])
    assert picked and all(mutants.repo_path(m[1]) == "fleet/internal/admin/admin.go" for m in picked)


@pytest.mark.parametrize("changed", [[], ["docs/agent.md", "CHANGELOG.md"], ["agent/internal/clock/clock.go"],
                                     ["agent/internal/clock/clock_test.go"], ["agent/internal/apply/visit.go"]])
def test_no_mutated_file_and_no_harness_change_runs_none(changed):
    picked, why = mutants.select_changed(ALL, changed)
    assert picked == []
    assert "no mutant to run" in why


@pytest.mark.parametrize("n", [1, 2, 4, 7])
def test_shards_are_disjoint_cover_the_list_and_are_even(n):
    parts = [mutants.shard(ALL, i, n) for i in range(1, n + 1)]
    assert sorted(m for p in parts for m in p) == sorted(ALL)
    assert sum(len(p) for p in parts) == len(ALL)
    assert max(map(len, parts)) - min(map(len, parts)) <= 1
    assert parts == [mutants.shard(ALL, i, n) for i in range(1, n + 1)]   # the same split every run


def test_shard_takes_i_of_n():
    assert mutants.parse_shard("2/4") == (2, 4)
    for bad in ["0/4", "5/4", "4", "a/b", "1/2/3", "1/0"]:
        with pytest.raises(argparse.ArgumentTypeError):
            mutants.parse_shard(bad)


def _git(repo, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgSign=false",
                           *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def test_changed_files_are_the_branch_since_base_plus_uncommitted(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.go").write_text("a\n")
    (tmp_path / "b.go").write_text("b\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "checkout", "-qb", "topic")
    (tmp_path / "a.go").write_text("a2\n")
    _git(tmp_path, "commit", "-qam", "topic")
    _git(tmp_path, "checkout", "-q", "main")
    (tmp_path / "c.go").write_text("c\n")      # a later commit on main is not part of the branch
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "main moves on")
    _git(tmp_path, "checkout", "-q", "topic")
    (tmp_path / "b.go").write_text("b2\n")     # uncommitted
    monkeypatch.chdir(tmp_path)
    assert sorted(mutants.changed_files("main")) == ["a.go", "b.go"]
    with pytest.raises(SystemExit):           # an unknown base stops the run instead of selecting nothing
        mutants.changed_files("no-such-ref")


def test_main_runs_nothing_when_nothing_is_selected(monkeypatch, capsys):
    monkeypatch.setattr(mutants, "changed_files", lambda base: ["docs/agent.md"])
    monkeypatch.setattr(mutants.subprocess, "run", lambda *a, **k: pytest.fail("ran go test"))
    assert mutants.main(["--changed", "origin/main", "--shard", "1/4"]) == 0
    out = capsys.readouterr().out
    assert "no mutant to run" in out and "0/0 mutants killed" in out

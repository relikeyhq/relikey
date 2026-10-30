# SPDX-License-Identifier: EUPL-1.2
"""The release gate (tools/release_gate.py): only a commit whose CI run on main passed is built and released."""
import pytest

from tools import release_gate as gate

SHA = "0123456789abcdef0123456789abcdef01234567"


def _run(status="completed", conclusion="success", sha=SHA, branch="main", event="push"):
    return {"head_sha": sha, "head_branch": branch, "event": event, "status": status, "conclusion": conclusion}


def test_a_passing_ci_run_on_main_passes():
    assert gate.verdict([_run()], SHA)[0] == "passed"


def test_a_rerun_that_passed_counts_beside_a_failed_attempt():
    assert gate.verdict([_run(conclusion="failure"), _run()], SHA)[0] == "passed"


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "skipped", "action_required"])
def test_a_run_that_did_not_pass_fails(conclusion):
    state, why = gate.verdict([_run(conclusion=conclusion)], SHA)
    assert state == "failed" and conclusion in why


def test_no_run_fails():
    state, why = gate.verdict([], SHA)
    assert state == "failed" and "no CI run on main" in why


@pytest.mark.parametrize("other", [
    _run(event="pull_request"),          # a pull request run tests a merge with the base, not this commit
    _run(branch="feature"),              # a commit that never reached main
    _run(sha="f" * 40),                  # another commit
])
def test_only_a_push_run_on_main_for_this_commit_counts(other):
    assert gate.verdict([other], SHA)[0] == "failed"


@pytest.mark.parametrize("status", ["queued", "in_progress", "waiting", "requested", "pending"])
def test_a_run_in_progress_is_waited_for(status):
    assert gate.verdict([_run(status=status, conclusion=None)], SHA)[0] == "pending"


def _api(monkeypatch, pages):
    """gh api stand-in: the tag resolves to SHA, and each poll of the runs takes the next page."""
    calls = []

    def gh_api(path):
        calls.append(path)
        if "/commits/" in path:
            return {"sha": SHA}
        return {"workflow_runs": pages.pop(0) if len(pages) > 1 else pages[0]}
    monkeypatch.setattr(gate, "gh_api", gh_api)
    monkeypatch.setattr(gate.time, "sleep", lambda s: None)
    return calls


def test_the_gate_waits_for_a_run_in_progress_then_passes(monkeypatch):
    calls = _api(monkeypatch, [[_run(status="in_progress", conclusion=None)], [_run()]])
    assert gate.main(["--repo", "o/r", "--tag", "v0.2.0"]) == 0
    assert calls[0] == "repos/o/r/commits/refs/tags/v0.2.0"
    assert all(f"head_sha={SHA}" in c and "branch=main" in c and "event=push" in c for c in calls[1:])


def test_the_gate_fails_a_tag_without_green_ci(monkeypatch):
    _api(monkeypatch, [[_run(conclusion="failure")]])
    assert gate.main(["--repo", "o/r", "--tag", "v0.2.0"]) == 1


def test_the_gate_stops_waiting_at_its_deadline(monkeypatch):
    _api(monkeypatch, [[_run(status="queued", conclusion=None)]])
    assert gate.main(["--repo", "o/r", "--tag", "v0.2.0", "--wait-minutes", "0"]) == 1

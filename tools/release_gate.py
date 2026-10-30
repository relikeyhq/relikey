#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""The release gate: a tag is built only when CI passed on its commit on main (release.yml, before any build).

  python tools/release_gate.py --repo OWNER/NAME --tag vX.Y.Z [--wait-minutes 45]

It resolves the tag to its commit and asks the GitHub API (through `gh`, with the workflow's token in GH_TOKEN) for the
CI workflow's runs on that commit, pushed to main. A successful run passes; a run still queued or in progress is
waited for; no run, or only failed or cancelled ones, fails the release before anything is built. A commit that never
reached main has no such run, so it is never released. If a later merge cancelled the run, re-run it, then the
release job.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

CI_WORKFLOW = "ci.yml"
PENDING = {"queued", "in_progress", "waiting", "requested", "pending"}


def verdict(runs: list[dict], sha: str) -> tuple[str, str]:
    """("passed" | "pending" | "failed", why) for the CI runs the API listed. Only a push run on main for exactly this
    commit counts, whatever the query asked for: a pull request run tests a merge with the base, not this commit."""
    ours = [r for r in runs if r.get("head_sha") == sha and r.get("head_branch") == "main" and r.get("event") == "push"]
    if any(r.get("status") == "completed" and r.get("conclusion") == "success" for r in ours):
        return "passed", f"CI passed on {sha[:12]} on main"
    if any(r.get("status") in PENDING for r in ours):
        return "pending", f"CI is still running on {sha[:12]}"
    if not ours:
        return "failed", f"no CI run on main for {sha[:12]}: tag a commit on main after its CI run passed"
    seen = ", ".join(sorted({str(r.get("conclusion")) for r in ours}))
    return "failed", f"CI did not pass on {sha[:12]} ({seen}): re-run it, or fix it on main and tag the next version"


def gh_api(path: str) -> dict:
    r = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"gh api {path} failed: {r.stderr.strip()}")
    return json.loads(r.stdout)


def tag_commit(repo: str, tag: str) -> str:
    """The commit a tag names (an annotated tag is followed to its commit)."""
    return gh_api(f"repos/{repo}/commits/refs/tags/{tag}")["sha"]


def ci_runs(repo: str, sha: str) -> list[dict]:
    return gh_api(f"repos/{repo}/actions/workflows/{CI_WORKFLOW}/runs?head_sha={sha}&branch=main&event=push"
                  "&per_page=100")["workflow_runs"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fail a release whose commit has no passing CI run on main.")
    ap.add_argument("--repo", required=True, help="OWNER/NAME")
    ap.add_argument("--tag", required=True, help="the release tag, vX.Y.Z")
    ap.add_argument("--wait-minutes", type=int, default=45, help="how long to wait for a CI run still in progress")
    a = ap.parse_args(argv)
    sha = tag_commit(a.repo, a.tag)
    deadline = time.monotonic() + a.wait_minutes * 60
    while True:
        state, why = verdict(ci_runs(a.repo, sha), sha)
        print(why, flush=True)
        if state == "passed":
            return 0
        if state == "failed" or time.monotonic() > deadline:
            return 1
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())

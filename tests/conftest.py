# SPDX-License-Identifier: EUPL-1.2
"""Tests run apart from the repository that runs them.

A pre-push hook runs this suite with git's repository variables set (GIT_DIR, GIT_INDEX_FILE and the rest), and from a
worktree GIT_DIR is an absolute path. A test that builds a scratch repository would then commit, tag and set config in
the repository being pushed. git names the variables itself (`git rev-parse --local-env-vars`); they are dropped once,
before any test runs.
"""
import os
import subprocess

for _name in subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True, text=True,
                            check=True).stdout.split():
    os.environ.pop(_name, None)

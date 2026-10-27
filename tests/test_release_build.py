# SPDX-License-Identifier: EUPL-1.2
"""The release build accepts the tag release.yml runs on (v0.1.0 failed: the workflow ran on v*, build.py wanted agent-v*)."""
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("agent_build", ROOT / "agent" / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "tag.gpgSign=false",
                    "-c", "commit.gpgSign=false", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "one")
    return tmp_path


def _workflow_tag_patterns():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    m = re.search(r"tags:\s*\[([^\]]*)\]", text)
    return [p.strip().strip("\"'") for p in m.group(1).split(",")]


@pytest.mark.parametrize("tag", ["v0.1.0", "v1.2.3", "agent-v0.0.9"])
def test_a_release_tag_on_head_is_found(repo, tag):
    _git(repo, "tag", "-a", tag, "-m", tag)
    assert build.release_tag(repo) == tag


@pytest.mark.parametrize("tag", ["nightly", "vnext", "release-1"])
def test_other_tags_are_not_releases(repo, tag):
    _git(repo, "tag", "-a", tag, "-m", tag)
    assert build.release_tag(repo) == ""


def test_the_tag_the_workflow_runs_on_is_one_build_accepts(repo):
    patterns = _workflow_tag_patterns()
    assert patterns == ["v*"], "release.yml's tag filter changed: check release_tag() still accepts it"
    _git(repo, "tag", "-a", "v0.1.0", "-m", "v0.1.0")
    assert build.release_tag(repo) == "v0.1.0"

# SPDX-License-Identifier: EUPL-1.2
"""Changelog fragments: the checks refuse what would break CHANGELOG.md, and release folds them in Keep a Changelog order."""
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("changelog", ROOT / "tools" / "changelog.py")
changelog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changelog)

HEAD = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n"
OLD = "## [0.1.2] - 2026-10-27\n\n### Fixed\n- The old fix.\n"


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "changelog.d").mkdir()
    (tmp_path / "changelog.d" / "README.md").write_text("How to add an entry.\n")
    (tmp_path / "CHANGELOG.md").write_text(HEAD + "### Changed\n- Already merged.\n\n" + OLD)
    return tmp_path


def frag(tree, name, text):
    (tree / "changelog.d" / name).write_text(text, encoding="utf-8")


def test_the_repository_fragments_are_well_formed():
    assert changelog.check(ROOT) == []


@pytest.mark.parametrize("name,text,why", [
    ("19.fix.md", "- A fix.\n", "unknown section"),
    ("fix-19.md", "- A fix.\n", "name it"),
    ("19.fixed.txt", "- A fix.\n", None),                       # not a .md file: not a fragment at all
    ("19.fixed.md", "", "empty"),
    ("19.fixed.md", "A fix.\n", "start with a '- ' bullet"),
    ("19.fixed.md", "- A fix\nthat wraps flush.\n", "continuation"),
    ("19.fixed.md", "- A fix.\n\n- Another.\n", "continuation"),
    ("19.fixed.md", "- " + "x" * 119 + "\n", "wrap at 120"),
    ("19.fixed.md", "- A “quoted” fix.\n", "non-ASCII"),
])
def test_check_refuses_a_malformed_fragment(tree, name, text, why):
    frag(tree, name, text)
    bad = changelog.check(tree)
    if why is None:
        assert bad == []
    else:
        assert len(bad) >= 1 and why in bad[0], bad


def test_check_accepts_bullets_with_continuations(tree):
    frag(tree, "19.fixed.md", "- A fix that is long enough\n  to wrap.\n- A second one.\n")
    frag(tree, "model-audit.changed.md", "- A slug-named entry.\n")
    assert changelog.check(tree) == []


def test_release_folds_fragments_in_order_and_removes_them(tree):
    frag(tree, "53.added.md", "- Metric names pinned.\n")
    frag(tree, "9.added.md", "- Activation by code.\n")
    frag(tree, "19.fixed.md", "- A retry\n  within a tick.\n")
    frag(tree, "model-audit.changed.md", "- Statuses with evidence.\n")
    changelog.release(tree, "0.2.0", "2026-11-01")
    text = (tree / "CHANGELOG.md").read_text()
    assert text == (HEAD + "## [0.2.0] - 2026-11-01\n\n"
                    "### Added\n- Activation by code.\n- Metric names pinned.\n\n"
                    "### Changed\n- Already merged.\n- Statuses with evidence.\n\n"
                    "### Fixed\n- A retry\n  within a tick.\n\n" + OLD)
    assert [p.name for p in (tree / "changelog.d").iterdir()] == ["README.md"]


def test_the_release_section_is_what_release_yml_reads(tree):
    """release.yml takes the lines after '## [X.Y.Z]' up to the next '## ' heading as the release notes."""
    frag(tree, "19.fixed.md", "- A retry.\n")
    changelog.release(tree, "0.2.0", "2026-11-01")
    lines, on = [], False
    for line in (tree / "CHANGELOG.md").read_text().splitlines():
        if line.startswith("## [0.2.0]"):
            on = True
            continue
        if line.startswith("## "):
            on = False
        if on:
            lines.append(line)
    assert "\n".join(lines).strip() == "### Changed\n- Already merged.\n\n### Fixed\n- A retry."


def test_release_refuses_a_bad_version_an_existing_one_bad_fragments_and_nothing(tree):
    with pytest.raises(SystemExit, match="X.Y.Z"):
        changelog.release(tree, "v0.2.0", "2026-11-01")
    with pytest.raises(SystemExit, match="already has a section.*is tagged"):
        changelog.release(tree, "0.1.2", "2026-11-01", tagged=lambda *a: True)
    frag(tree, "19.fix.md", "- A fix.\n")
    with pytest.raises(SystemExit, match="fix the fragments"):
        changelog.release(tree, "0.2.0", "2026-11-01")
    (tree / "changelog.d" / "19.fix.md").unlink()
    (tree / "CHANGELOG.md").write_text(HEAD + OLD)
    with pytest.raises(SystemExit, match="nothing to release"):
        changelog.release(tree, "0.2.0", "2026-11-01")


def test_release_refuses_an_unknown_section_already_in_unreleased(tree):
    (tree / "CHANGELOG.md").write_text(HEAD + "### Not yet done\n- Something.\n\n" + OLD)
    with pytest.raises(SystemExit, match="unknown section"):
        changelog.release(tree, "0.2.0", "2026-11-01")


def _notes_step():
    """The run block of release-build.yml's step that writes notes/notes.md."""
    import yaml
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "release-build.yml").read_text(encoding="utf-8"))
    step = next(s for s in wf["jobs"]["build"]["steps"] if s.get("name", "").startswith("Take the release notes"))
    return step["run"]


@pytest.mark.skipif(os.name == "nt", reason="the workflow step is bash on Linux runners")
@pytest.mark.parametrize("tag,first,has", [
    ("v0.3.0-rc.1", "Release candidate for 0.3.0, not a release.", "- A retry."),   # the unreleased fragments
    ("v0.1.2", "", "- The old fix."),                                                  # the version's own section
])
def test_the_release_notes_step_takes_a_candidate_from_the_fragments(tree, tag, first, has):
    (tree / "tools").mkdir()
    shutil.copy(ROOT / "tools" / "changelog.py", tree / "tools" / "changelog.py")
    frag(tree, "19.fixed.md", "- A retry.\n")
    env = {**os.environ, "GITHUB_REF_NAME": tag, "GITHUB_REPOSITORY": "o/r"}
    subprocess.run(["bash", "-e", "-c", _notes_step()], cwd=tree, env=env, check=True)
    notes = (tree / "notes" / "notes.md").read_text(encoding="utf-8")
    assert notes.startswith(first) and has in notes


@pytest.mark.skipif(os.name == "nt", reason="the workflow step is bash on Linux runners")
def test_the_release_notes_step_refuses_a_version_without_changes(tree):
    env = {**os.environ, "GITHUB_REF_NAME": "v0.9.0", "GITHUB_REPOSITORY": "o/r"}
    r = subprocess.run(["bash", "-e", "-c", _notes_step()], cwd=tree, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "no changes for 0.9.0" in r.stderr


def test_a_candidate_is_published_as_a_pre_release():
    import yaml
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    run = next(s["run"] for s in wf["jobs"]["github-release"]["steps"] if "gh release create" in s.get("run", ""))
    assert "--prerelease" in run and '*-*' in run


def test_an_untagged_section_takes_the_fragments_since(tree):
    """v0.3.0's section was folded on 2026-11-06, before six release candidates found the bugs the fragments since
    then fix; untagged, it takes them and the release date, keeping what it held."""
    frag(tree, "19.fixed.md", "- The new fix.\n")
    frag(tree, "slug.added.md", "- A new thing.\n")
    out = changelog.release(tree, "0.1.2", "2026-11-07", tagged=lambda *a: False)
    text = (tree / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "folded 2 fragment(s)" in out and "## [0.1.2] - 2026-11-07" in text and "2026-10-27" not in text
    section = text[text.index("## [0.1.2]"):]
    assert section.index("### Added") < section.index("### Fixed")
    assert "- A new thing." in section and "- The old fix." in section and "- The new fix." in section
    assert "- Already merged." in text[:text.index("## [0.1.2]")]   # [Unreleased] is left alone
    assert [p.name for p in (tree / "changelog.d").glob("*.md")] == ["README.md"]
    with pytest.raises(SystemExit, match="nothing to add"):
        changelog.release(tree, "0.1.2", "2026-11-07", tagged=lambda *a: False)


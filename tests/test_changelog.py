# SPDX-License-Identifier: EUPL-1.2
"""Changelog fragments: the checks refuse what would break CHANGELOG.md, and release folds them in Keep a Changelog order."""
import importlib.util
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
    with pytest.raises(SystemExit, match="already has a section"):
        changelog.release(tree, "0.1.2", "2026-11-01")
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

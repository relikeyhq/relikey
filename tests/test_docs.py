# SPDX-License-Identifier: EUPL-1.2
"""The docs check: generated reference pages are current, every agent.json field is described, links resolve."""

import pytest

from tools import docs


def test_reference_is_current_and_links_resolve(capsys):
    assert docs.main.__module__ == "tools.docs"
    import sys
    argv = sys.argv
    sys.argv = ["docs.py", "check"]
    try:
        assert docs.main() == 0, capsys.readouterr().out
    finally:
        sys.argv = argv


def test_a_stale_page_fails(tmp_path, monkeypatch, capsys):
    import shutil
    import sys
    out = tmp_path / "reference"
    shutil.copytree(docs.OUT, out)
    (out / "flows.md").write_text((out / "flows.md").read_text(encoding="utf-8") + "\nhand edit\n", encoding="utf-8")
    monkeypatch.setattr(docs, "OUT", out)
    monkeypatch.setattr(sys, "argv", ["docs.py", "check"])
    assert docs.main() == 1
    assert "docs/reference/flows.md is stale" in capsys.readouterr().out


def test_an_undocumented_config_field_fails(tmp_path, monkeypatch):
    src = docs.AGENT_MAIN.read_text(encoding="utf-8")
    marker = "\t// How often the agent pulls a bundle from the desk, in seconds (default 60).\n"
    assert marker in src
    fake = tmp_path / "main.go"
    fake.write_text(src.replace(marker, ""), encoding="utf-8")
    monkeypatch.setattr(docs, "AGENT_MAIN", fake)
    _, missing = docs.agent_config()
    assert missing == ["pull_seconds"]


def test_a_broken_link_is_found(tmp_path, monkeypatch):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("see [b](b.md) and [web](https://example.test)\n", encoding="utf-8")
    monkeypatch.setattr(docs, "ROOT", tmp_path)
    bad = docs.broken_links()
    assert len(bad) == 1 and "b.md does not resolve" in bad[0]


@pytest.mark.parametrize("page", ["components.md", "contracts.md", "flows.md", "agent-config.md", "commands.md"])
def test_generated_pages_name_no_local_path(page):
    text = (docs.OUT / page).read_text(encoding="utf-8")
    assert "C:\\" not in text and "/home/" not in text and "\\Users\\" not in text

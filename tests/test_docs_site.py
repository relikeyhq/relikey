# SPDX-License-Identifier: EUPL-1.2
"""The site hook: a docs/ page's link to a file outside docs/ resolves on the site as it does in the repository."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("home", ROOT / "docs-site" / "home.py")
home = importlib.util.module_from_spec(spec)
spec.loader.exec_module(home)


def rewrite(markdown, src_uri="maintaining.md"):
    page = SimpleNamespace(file=SimpleNamespace(src_uri=src_uri))
    return home.on_page_markdown(markdown, page, None, None)


def test_a_repository_file_becomes_its_github_page():
    assert rewrite("[ROADMAP](../ROADMAP.md#next)") == f"[ROADMAP]({home.BLOB}ROADMAP.md#next)"


def test_the_readme_becomes_the_home_page():
    assert rewrite("[README](../README.md)") == "[README](index.md)"
    assert rewrite("[README](../../README.md)", "reference/commands.md") == "[README](../index.md)"


def test_links_inside_docs_and_external_links_are_left_alone():
    text = "[a](fleet.md) [b](reference/commands.md#x) [c](https://example.org/) [d](#top)"
    assert rewrite(text) == text

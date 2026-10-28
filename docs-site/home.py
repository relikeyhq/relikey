# SPDX-License-Identifier: EUPL-1.2
"""MkDocs hook: the repository README is the home page of the site.

The README lives at the repository root, outside docs_dir, so the build adds it as index.md and rewrites the two
kinds of link that only work from the root: docs/ pages become site-relative, and other repository files become links
to the file on GitHub.
"""
import re
from pathlib import Path

from mkdocs.structure.files import File

ROOT = Path(__file__).resolve().parent.parent
BLOB = "https://github.com/relikeyhq/relikey/blob/main/"


def _rewrite(match):
    text, target = match.group(1), match.group(2)
    if re.match(r"([a-z]+:|#)", target):
        return match.group(0)
    if target.startswith("docs/"):
        return f"[{text}]({target[len('docs/'):]})"
    return f"[{text}]({BLOB}{target})"


def on_files(files, config):
    files.append(File.generated(config, "index.md", content=_home()))
    return files


def _home():
    source = (ROOT / "README.md").read_text(encoding="utf-8")
    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _rewrite, source)

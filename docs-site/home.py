# SPDX-License-Identifier: EUPL-1.2
"""MkDocs hook: the repository README is the home page of the site.

The README lives at the repository root, outside docs_dir, so the build adds it as index.md and rewrites the two
kinds of link that only work from the root: docs/ pages become site-relative, and other repository files become links
to the file on GitHub. A docs/ page's link to a file outside docs/ (`../ROADMAP.md`) gets the same treatment: the
README becomes the home page, anything else the file on GitHub, so the repository view and the site both resolve it.
"""
import os
import re
from pathlib import Path, PurePosixPath

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


def on_page_markdown(markdown, page, config, files):
    here = PurePosixPath(page.file.src_uri).parent

    def outside(match):
        text, target = match.group(1), match.group(2)
        if re.match(r"([a-z]+:|#|/)", target):
            return match.group(0)
        path, _, anchor = target.partition("#")
        resolved = PurePosixPath(os.path.normpath((here / path).as_posix()).replace(os.sep, "/"))
        if not resolved.parts or resolved.parts[0] != "..":
            return match.group(0)
        repo_path = PurePosixPath(*resolved.parts[1:]).as_posix()
        if repo_path == "README.md":
            home = os.path.relpath("index.md", here.as_posix() or ".").replace(os.sep, "/")
            return f"[{text}]({home}{'#' + anchor if anchor else ''})"
        return f"[{text}]({BLOB}{repo_path}{'#' + anchor if anchor else ''})"

    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", outside, markdown)

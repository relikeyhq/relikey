# SPDX-License-Identifier: EUPL-1.2
"""Internal links in the docs resolve: every relative Markdown link points at a file that exists, and every #anchor
at a heading in its target. External links are not fetched."""

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
TOP = ("README.md", "ROADMAP.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md")
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^ {0,3}(```|~~~)")


def doc_files() -> list[Path]:
    files = [ROOT / t for t in TOP if (ROOT / t).exists()]
    return files + sorted((ROOT / "docs").rglob("*.md"))


def prose_lines(path: Path):
    """(number, line) outside fenced code blocks, with inline code spans blanked."""
    fenced = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield n, re.sub(r"`[^`]*`", "", line)


def slug(heading: str) -> str:
    """GitHub heading anchor: link text and markup dropped, lowercase, punctuation dropped, spaces to hyphens."""
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    h = re.sub(r"[`*_~]", "", h).strip().lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out = set()
    for _, line in prose_lines(path):
        m = HEADING.match(line)
        if m:
            s = slug(m.group(1))
            k = seen.get(s, 0)
            seen[s] = k + 1
            out.add(s if k == 0 else f"{s}-{k}")
    return out


def broken_links() -> list[str]:
    bad = []
    cache: dict[Path, set[str]] = {}
    for f in doc_files():
        for n, line in prose_lines(f):
            for target in LINK.findall(line):
                if re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
                    continue
                name, _, frag = target.partition("#")
                dest = (f.parent / unquote(name)).resolve() if name else f
                where = f"{f.relative_to(ROOT).as_posix()}:{n}: {target}"
                if not dest.exists():
                    bad.append(f"{where}: no such file")
                elif frag and dest.suffix == ".md":
                    if dest not in cache:
                        cache[dest] = anchors(dest)
                    if unquote(frag).lower() not in cache[dest]:
                        bad.append(f"{where}: no such heading")
    return bad


def test_internal_links_resolve():
    assert broken_links() == []


def test_slug_follows_github():
    assert slug("What it is, and why (v2)") == "what-it-is-and-why-v2"
    assert slug("The `agent.json` file") == "the-agentjson-file"


def test_anchors_handle_duplicates_and_fences(tmp_path):
    page = tmp_path / "p.md"
    page.write_text("# Intro\n\n## Setup\n\n```\n# not a heading\n```\n\n## Setup\n", encoding="utf-8")
    assert anchors(page) == {"intro", "setup", "setup-1"}

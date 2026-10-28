#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Changelog fragments: each pull request adds a file under changelog.d/ instead of editing CHANGELOG.md.

Every open pull request used to append to the same `## [Unreleased]` list, so each merge made the next one conflict.
A fragment is its own file and never conflicts. Its name is `<id>.<section>.md`: the issue number (or a short slug)
and the Keep a Changelog section, for example `changelog.d/19.fixed.md`. It holds Markdown bullets in the style of
CHANGELOG.md: a line starting "- ", continuation lines indented two spaces, at most 120 columns, ASCII only.

  python tools/changelog.py check              # the fragments are well formed (CI runs it through pytest)
  python tools/changelog.py show               # the [Unreleased] section with the fragments folded in
  python tools/changelog.py release 0.2.0      # write ## [0.2.0] - <today> and remove the fragments

release runs on a branch for the release pull request; the tag follows its merge (docs/publishing.md).
"""
import argparse
import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECTIONS = ("added", "changed", "deprecated", "removed", "fixed", "security")    # Keep a Changelog 1.1.0 order
NAME = re.compile(r"^(?P<id>[a-z0-9][a-z0-9-]*)\.(?P<section>[a-z]+)\.md$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
WIDTH = 120


def fragments(root: Path) -> list[Path]:
    d = root / "changelog.d"
    return sorted(p for p in d.glob("*.md") if p.name != "README.md") if d.is_dir() else []


def order(path: Path):
    """Issue numbers in numeric order, then slugs."""
    i = NAME.match(path.name)["id"]
    return (0, int(i), "") if i.isdigit() else (1, 0, i)


def problems(path: Path) -> list[str]:
    m = NAME.match(path.name)
    if not m:
        return [f"{path.name}: name it <issue>.<section>.md, for example 19.fixed.md"]
    if m["section"] not in SECTIONS:
        return [f"{path.name}: unknown section {m['section']!r}; use one of {', '.join(SECTIONS)}"]
    text = path.read_text(encoding="utf-8")
    lines = text.rstrip("\n").split("\n")
    out = []
    if not text.strip():
        return [f"{path.name}: empty; write at least one '- ' bullet"]
    if not lines[0].startswith("- "):
        out.append(f"{path.name}:1: start with a '- ' bullet")
    for n, line in enumerate(lines, 1):
        if not (line.startswith("- ") or (line.startswith("  ") and line.strip())):
            out.append(f"{path.name}:{n}: a line is a '- ' bullet or a continuation indented two spaces")
        if len(line) > WIDTH:
            out.append(f"{path.name}:{n}: {len(line)} columns; wrap at {WIDTH}")
        if not line.isascii():
            out.append(f"{path.name}:{n}: non-ASCII character; use straight quotes and plain hyphens")
    return out


def check(root: Path) -> list[str]:
    return [p for f in fragments(root) for p in problems(f)]


def split_unreleased(text: str):
    """(before, unreleased body, after): the body runs from the heading to the next `## ` heading."""
    m = re.search(r"^## \[Unreleased\][ \t]*\n", text, re.M)
    if not m:
        raise SystemExit("CHANGELOG.md has no '## [Unreleased]' heading")
    nxt = re.search(r"^## ", text[m.end():], re.M)
    end = m.end() + nxt.start() if nxt else len(text)
    return text[:m.end()], text[m.end():end], text[end:]


def merged(body: str, frags: list[Path]) -> str:
    """The [Unreleased] body with the fragments added under their sections, in Keep a Changelog order."""
    prose, entries, cur = [], {s: [] for s in SECTIONS}, None
    for line in body.strip("\n").split("\n") if body.strip() else []:
        h = re.match(r"^### (.+?)\s*$", line)
        if h:
            cur = h[1].lower()
            if cur not in entries:
                raise SystemExit(f"CHANGELOG.md [Unreleased] has an unknown section '### {h[1]}'")
        elif cur:
            entries[cur].append(line)
        else:
            prose.append(line)
    for f in sorted(frags, key=order):
        entries[NAME.match(f.name)["section"]] += f.read_text(encoding="utf-8").rstrip("\n").split("\n")
    parts = ["\n".join(prose).strip("\n")] if "".join(prose).strip() else []
    for s in SECTIONS:
        lines = [x for x in entries[s] if x.strip()]
        if lines:
            parts.append(f"### {s.capitalize()}\n" + "\n".join(lines))
    return "\n\n".join(parts)


def show(root: Path) -> str:
    _, body, _ = split_unreleased((root / "CHANGELOG.md").read_text(encoding="utf-8"))
    return merged(body, fragments(root))


def release(root: Path, version: str, date: str) -> str:
    if not VERSION.match(version):
        raise SystemExit(f"{version!r} is not X.Y.Z (the tag is vX.Y.Z)")
    if bad := check(root):
        raise SystemExit("fix the fragments first:\n" + "\n".join(bad))
    path = root / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    if re.search(rf"^## \[{re.escape(version)}\]", text, re.M):
        raise SystemExit(f"CHANGELOG.md already has a section for {version}; release tags never move (docs/publishing.md)")
    before, body, after = split_unreleased(text)
    frags = fragments(root)
    section = merged(body, frags)
    if not section:
        raise SystemExit("nothing to release: [Unreleased] and changelog.d/ are empty")
    path.write_text(f"{before}\n## [{version}] - {date}\n\n{section}\n\n{after}", encoding="utf-8", newline="\n")
    for f in frags:
        f.unlink()
    return section


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("show")
    r = sub.add_parser("release")
    r.add_argument("version")
    r.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args(argv)
    if a.cmd == "check":
        bad = check(ROOT)
        print("\n".join(bad) or f"changelog.d: {len(fragments(ROOT))} fragment(s) ok")
        return 1 if bad else 0
    if a.cmd == "show":
        print(show(ROOT))
        return 0
    print(release(ROOT, a.version, a.date))
    print(f"\nCHANGELOG.md has ## [{a.version}]; commit it with the removed fragments in the release pull request")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Curated public-export + leak gate for ReliKey (go-public plan).

Fail-closed. Every git-tracked file is classified public or holdback from
tools/publish-manifest.yaml; an unclassified file fails the export. Public files are
staged into an output tree, scanned for hard-fail identifiers (operator name, local
paths) and flagged for human review (attack detail, infra), and gitleaks runs on the
staged tree as the secret backstop.

This tool NEVER pushes or creates anything. Creating the public org and repository and
pushing the export is the operator's gate-governed action.

Exit codes: 0 clean, 2 unclassified file(s), 3 hard-fail match, 4 gitleaks finding,
5 gitleaks missing under --strict.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "tools" / "publish-manifest.yaml"


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def matches(path: str, entry: str) -> bool:
    return path.startswith(entry) if entry.endswith("/") else path == entry


def classify(path: str, public: list[str], holdback: list[str]) -> str:
    if any(matches(path, h) for h in holdback):
        return "holdback"
    if any(matches(path, p) for p in public):
        return "public"
    return "unclassified"


def scan_content(files: list[str], patterns: list[str]) -> list[tuple[str, int, str]]:
    compiled = [(p, re.compile(p)) for p in patterns]
    hits: list[tuple[str, int, str]] = []
    for rel in files:
        f = REPO / rel
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, rx in compiled:
                if rx.search(line):
                    hits.append((rel, lineno, pat))
    return hits


def run_gitleaks(staged: Path, strict: bool) -> tuple[int, str]:
    if shutil.which("gitleaks") is None:
        return (5 if strict else 0), "gitleaks not on PATH"
    cmd = ["gitleaks", "detect", "--source", str(staged), "--no-git", "--redact",
           "--exit-code", "4"]
    cfg = REPO / ".gitleaks.toml"
    if cfg.exists():
        cmd += ["--config", str(cfg)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    detail = (proc.stdout + proc.stderr).strip()
    # 0 = clean, 4 = findings; anything else (e.g. 1 = bad config) is a gate failure,
    # not a pass - never let a gitleaks error through as clean.
    if proc.returncode not in (0, 4):
        return 4, f"gitleaks error (exit {proc.returncode}): {detail}"
    return proc.returncode, detail


LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
BARE = re.compile(r"(?<![\w/.-])((?:\.\./)*(?:docs/)?reviews/[\w./-]+\.md)")   # links are handled before this
LAB = re.compile(r"`?(?<![\w/.-])(?:\.\./)*lab/[\w./*-]*`?")   # the lab harness is held back


def neutralise_holdback_links(staged: Path, rel: str, holdback: list[str]) -> int:
    """In a staged markdown file, a link or path into held-back material would be dead in public: keep its words, drop
    the target. The private repo keeps working links; only the staged copy changes."""
    f = staged / rel
    text = f.read_text(encoding="utf-8")
    base = Path(rel).parent

    def held(target: str) -> bool:
        if "://" in target or target.startswith("#"):
            return False
        p = (base / target.split("#")[0]).as_posix()
        parts = []
        for seg in p.split("/"):
            if seg == "..":
                parts = parts[:-1]
            elif seg not in ("", "."):
                parts.append(seg)
        resolved = "/".join(parts)
        return any(matches(resolved, h) or resolved.startswith(h.rstrip("/")) for h in holdback)

    n = 0

    def link(m):
        nonlocal n
        if held(m.group(2)):
            n += 1
            return f"{m.group(1)} (record kept with the maintainer)"
        return m.group(0)

    def bare(m):
        nonlocal n
        path = m.group(1)                        # a "docs/..." mention is from the repo root, "../" from this file
        root_rel = path.startswith(("docs/", "reviews/"))
        if (any(matches(path, h) or path.startswith(h.rstrip("/")) for h in holdback) if root_rel else held(path)):
            n += 1
            return "a review record kept with the maintainer"
        return m.group(0)

    def lab(m):
        nonlocal n
        n += 1
        return "the lab harness (kept with the maintainer)"

    new = LAB.sub(lab, BARE.sub(bare, LINK.sub(link, text)))
    if new != text:
        f.write_text(new, encoding="utf-8")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(REPO / "build" / "public-export"),
                    help="staging directory for the public tree")
    ap.add_argument("--strict", action="store_true",
                    help="fail if gitleaks is not installed")
    ap.add_argument("--snapshot", metavar="VERSION",
                    help="after every check passes, commit the staged tree to the local publish/snapshot branch")
    args = ap.parse_args()

    m = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    public, holdback = m["public"], m["holdback"]
    review_flags, hard_fail = m.get("review_flags", []), list(m.get("hard_fail", []))
    private = REPO / "tools" / "publish-private.yaml"   # held back; absent in a public checkout
    if private.exists():
        priv = yaml.safe_load(private.read_text(encoding="utf-8"))
        hard_fail += priv.get("hard_fail", [])
        review_flags = review_flags + priv.get("review_flags", [])

    files = tracked_files()
    buckets: dict[str, list[str]] = {"public": [], "holdback": [], "unclassified": []}
    for rel in files:
        buckets[classify(rel, public, holdback)].append(rel)

    print(f"tracked={len(files)} public={len(buckets['public'])} "
          f"holdback={len(buckets['holdback'])} unclassified={len(buckets['unclassified'])}")

    if buckets["unclassified"]:
        print("\nUNCLASSIFIED (classify each in publish-manifest.yaml before exporting):")
        for rel in buckets["unclassified"]:
            print(f"  {rel}")
        return 2

    # stage the public tree
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    for rel in buckets["public"]:
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)
    dead = sum(neutralise_holdback_links(out, rel, holdback) for rel in buckets["public"] if rel.endswith(".md"))
    print(f"links into held-back material neutralised in the staged copy: {dead}")

    hard = scan_content(buckets["public"], hard_fail)
    if hard:
        print("\nHARD-FAIL (operator identity / local paths must not be published):")
        for rel, lineno, pat in hard:
            print(f"  {rel}:{lineno}  /{pat}/")
        return 3

    flags = scan_content(buckets["public"], review_flags)
    if flags:
        print("\nREVIEW BEFORE FLIP (human must eyeball - attack detail / infra / residuals):")
        for rel, lineno, pat in flags:
            print(f"  {rel}:{lineno}  /{pat}/")

    print("\nHELD BACK (kept private):")
    for rel in buckets["holdback"]:
        print(f"  {rel}")

    code, detail = run_gitleaks(out, args.strict)
    print(f"\ngitleaks: {'clean' if code == 0 else 'ATTENTION'} ({detail or 'no findings'})")
    if code in (4, 5):
        return code

    print(f"\nStaged public export at {out}")
    if args.snapshot:
        print(f"snapshot: {snapshot(out, args.snapshot)}")
    print("This tool does not push. Creating the public org/repo and pushing is the operator's action.")
    return 0


def snapshot(out: Path, version: str) -> str:
    """Commit the staged tree to the local publish/snapshot branch, one commit per release on top of the last one (the
    neurokeeper pattern): the public history is the releases, never the private history behind them. The identity is
    the product's steward, from the held-back tools/publish-private.yaml (snapshot_identity) - a release is cut from the
    private repository only. Only after every check above passed; never pushed here."""
    import os
    import tempfile
    private = REPO / "tools" / "publish-private.yaml"
    who = (yaml.safe_load(private.read_text(encoding="utf-8")) or {}).get("snapshot_identity") if private.exists() else None
    if not who or not who.get("name") or not who.get("email"):
        sys.exit("snapshot: no snapshot_identity {name, email} in tools/publish-private.yaml - a release is cut from the "
                 "private repository with the steward's identity (estate rules); nothing was committed")
    ident = {"GIT_AUTHOR_NAME": who["name"], "GIT_AUTHOR_EMAIL": who["email"],
             "GIT_COMMITTER_NAME": who["name"], "GIT_COMMITTER_EMAIL": who["email"]}
    with tempfile.TemporaryDirectory() as td:
        env = {**os.environ, **ident, "GIT_INDEX_FILE": str(Path(td) / "index")}
        def g(*a):
            return subprocess.run(["git", "-C", str(REPO), *a], env=env, capture_output=True, text=True)

        if g("--work-tree", str(out), "add", "-A", ".").returncode != 0:
            sys.exit("snapshot: could not stage the export tree")
        tree = g("write-tree").stdout.strip()
        parent = g("rev-parse", "--verify", "-q", "refs/heads/publish/snapshot").stdout.strip()
        commit = g("commit-tree", tree, *(["-p", parent] if parent else []), "-m", f"Publish {version} snapshot").stdout.strip()
        if not commit or g("update-ref", "refs/heads/publish/snapshot", commit, *([parent] if parent else [])).returncode:
            sys.exit("snapshot: could not record the commit on publish/snapshot")
    return f"publish/snapshot at {commit[:12]} ({'on ' + parent[:12] if parent else 'first snapshot'}), {version}"


if __name__ == "__main__":
    sys.exit(main())

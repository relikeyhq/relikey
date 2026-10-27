#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Contribution-time leak gate for the public repository (decision 0027).

Everything pushed or posted to the public repository is public at once: diffs, commit messages, issue text, pull
request bodies and comments. This check scans that text with the export's patterns: identity and local paths are hard
failures, attack detail and infrastructure are flags a human reads before the text goes out.

  public_text_check.py --text body.md          an issue, pull request or comment text ('-' reads stdin)
  public_text_check.py --range BASE..HEAD      added diff lines and commit messages, plus gitleaks on the commits

Patterns come from tools/publish-manifest.yaml (hard_fail, review_flags), from the held-back tools/publish-private.yaml
when present, and from RELIKEY_PRIVATE_PATTERNS (one hard-fail regex per line; a CI secret). Patterns that are not
public are reported by number only, so the report never publishes them.

Exit codes: 0 clean, 1 flags to read (0 with --flags-ok), 3 hard-fail match, 4 gitleaks finding, 5 gitleaks missing
under --strict.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "tools" / "publish-manifest.yaml"
PRIVATE = REPO / "tools" / "publish-private.yaml"


class Pattern:
    def __init__(self, regex: str, hard: bool, label: str):
        self.rx, self.hard, self.label = re.compile(regex), hard, label


def load_patterns(env: dict[str, str] | None = None) -> list[Pattern]:
    env = os.environ if env is None else env
    m = yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
    pats = [Pattern(p, True, p) for p in m.get("hard_fail", [])]
    pats += [Pattern(p, False, p) for p in m.get("review_flags", [])]
    private: list[tuple[str, bool]] = []
    if PRIVATE.exists():
        priv = yaml.safe_load(PRIVATE.read_text(encoding="utf-8")) or {}
        private += [(p, True) for p in priv.get("hard_fail", [])]
        private += [(p, False) for p in priv.get("review_flags", [])]
    private += [(p, True) for p in env.get("RELIKEY_PRIVATE_PATTERNS", "").splitlines() if p.strip()]
    pats += [Pattern(p, hard, f"private pattern {i}") for i, (p, hard) in enumerate(private, 1)]
    return pats


def scan(lines: list[tuple[str, str]], pats: list[Pattern]) -> list[tuple[str, Pattern, str]]:
    """lines: (where, text). Returns (where, pattern, text) for every match."""
    return [(where, p, text) for where, text in lines for p in pats if p.rx.search(text)]


def text_lines(source: str) -> list[tuple[str, str]]:
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8", errors="replace")
    return [(f"line {n}", line) for n, line in enumerate(text.splitlines(), 1)]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, check=True, capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


def range_lines(rng: str) -> list[tuple[str, str]]:
    base, head = rng.split("..", 1)
    out: list[tuple[str, str]] = []
    for sha in git("rev-list", rng).split():
        for n, line in enumerate(git("log", "-1", "--format=%B", sha).splitlines(), 1):
            out.append((f"commit {sha[:10]} message line {n}", line))
    path, lineno = "?", 0
    for line in git("diff", "--unified=0", "--no-color", base, head).splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            hit = re.search(r"\+(\d+)", line)
            lineno = int(hit.group(1)) if hit else 0
        elif line.startswith("+"):
            out.append((f"{path}:{lineno}", line[1:]))
            lineno += 1
    return out


def run_gitleaks(rng: str, strict: bool) -> tuple[int, str]:
    if shutil.which("gitleaks") is None:
        return (5 if strict else 0), "gitleaks not on PATH"
    cmd = ["gitleaks", "git", "--log-opts", rng, "--redact", "--no-banner", "--exit-code", "1"]
    cfg = REPO / ".gitleaks.toml"
    if cfg.exists():
        cmd += ["--config", str(cfg)]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    if proc.returncode == 0:
        return 0, ""
    # Any other exit is a finding or an error, never a pass.
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return 4, tail[-1] if tail else f"exit {proc.returncode}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="file with the text to post ('-' for stdin)")
    src.add_argument("--range", help="BASE..HEAD: added lines and commit messages")
    ap.add_argument("--flags-ok", action="store_true", help="flags were read by a human: report, do not fail")
    ap.add_argument("--strict", action="store_true", help="fail if gitleaks is not installed (--range)")
    args = ap.parse_args(argv)

    pats = load_patterns()
    lines = text_lines(args.text) if args.text else range_lines(args.range)
    hits = scan(lines, pats)
    hard = [h for h in hits if h[1].hard]
    flags = [h for h in hits if not h[1].hard]
    for where, p, _ in hard:
        print(f"HARD-FAIL {where}: {p.label}")
    for where, p, text in flags:
        shown = text.strip()[:160] if not p.label.startswith("private") else "(not shown)"
        print(f"flag {where}: {p.label}: {shown}")

    code = 3 if hard else 0
    if args.range:
        gl, detail = run_gitleaks(args.range, args.strict)
        if gl:
            print(f"gitleaks: {'not installed' if gl == 5 else 'ATTENTION'} {detail}".rstrip())
        code = code or gl
    if not code and flags and not args.flags_ok:
        print(f"{len(flags)} flag(s): read them; if the text is fine, re-run with --flags-ok")
        code = 1
    if not code:
        print(f"clean ({len(lines)} line(s), {len(flags)} flag(s) read)" if flags else f"clean ({len(lines)} line(s))")
    return code


if __name__ == "__main__":
    sys.exit(main())

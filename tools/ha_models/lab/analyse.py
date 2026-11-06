#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Reads ~/arblab/results (fetched): per scenario, the client's gaps (consecutive failed connects), which node answered
over time, both nodes' TAKE/RELEASE lines, and whether the address was ever answered by both within one second."""
import sys
import re
from pathlib import Path

R = Path(sys.argv[1])
for name in sorted({p.stem for p in R.glob("*.client")}):
    cl = [line.split() for line in (R / f"{name}.client").read_text().splitlines() if re.match(r"^\d", line)]
    ev = [line.split(None, 2) for line in (R / f"{name}.events").read_text().splitlines()] if (R / f"{name}.events").exists() else []
    t0 = float(ev[0][0]) if ev else float(cl[0][0])
    gaps, start, prev = [], None, None
    for t, who in ((float(a), b) for a, b in cl):
        if who == "-" and start is None:
            start = t
        if who != "-" and start is not None:
            gaps.append((round(start - t0, 1), round(t - start, 1)))
            start = None
    if start is not None:
        gaps.append((round(start - t0, 1), "until the end"))
    after = [b for a, b in cl if float(a) >= t0]
    seq = []
    for w in after:
        if not seq or seq[-1][0] != w:
            seq.append([w, 1])
        else:
            seq[-1][1] += 1
    flips = sum(1 for i in range(1, len(after)) if after[i] in "AB" and after[i - 1] in "AB" and after[i] != after[i - 1])
    acts = []
    for n in "ab":
        f = R / f"{name}.{n}"
        if f.exists():
            for line in f.read_text().splitlines():
                m = re.match(r"^(\d+\.\d+) (\w) (TAKE|RELEASE)", line)
                if m:
                    acts.append((round(float(m.group(1)) - t0, 1), m.group(2), m.group(3)))
    print(f"== {name}: events {[(round(float(e[0]) - t0, 1), e[2]) for e in ev]}")
    print(f"   gaps (start s after the first event, length s): {gaps}")
    print(f"   answers in order: {' '.join(f'{w}x{c}' for w, c in seq[:12])}; direct A/B flips: {flips}")
    print(f"   arbiter: {sorted(acts)}")

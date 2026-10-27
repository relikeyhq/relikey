# SPDX-License-Identifier: EUPL-1.2
"""ReliKey's master mark: the R as a serial connector, its leg a key (operator, 2026-10-24; BRAND.md).

    python brand/build_mark.py

Writes brand/mark/geometry.json (the master geometry on a 64 grid) and the mark files derived from it. Construction:
  - stem x 12-20, y 8-56; bowl outer radius 14 to x 46, counter radius 6: one evenodd path (a true knockout). The bowl
    is a D, as a D-sub connector's shell is;
  - the counter holds a DE-9's pins, 3 over 2, radius 1.6, in ink: the legacy connector. Dropped at 32 px and below
    (the `small` set), where they would only grey the counter;
  - the leg is the parallelogram between the lines (24,31)-(37,56) and (33,31)-(46,56). From y 31 to 40 it is ink, so
    the R's outline is unbroken and it never reads as a P; from y 40 down it is the key blade in the accent, with two
    square bits standing 4.5 out from its outer edge at y 43-47 and 50-54 (every feature >= 4 units: holds at 24 px);
  - the ink leg piece is its own path: in one evenodd path with the bowl their overlap would cancel;
  - everything shifted by DX so the mass is centred on x 32.
Every other brand file derives from geometry.json; change the mark here and rebuild (build_icons.py).
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DX = 1
BITS = [(43, 47), (50, 54)]
JOIN = 40                                           # where the ink leg becomes the orange blade
INK, INK_DARK = "#17142b", "#ffffff"
ACCENT, ACCENT_DARK = "#c85d16", "#f0954f"          # KeyClerk's orange: one family accent (operator, 2026-10-24)


def n(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return s or "0"


def on(x0: float, y: float) -> float:
    return x0 + 13 * (y - 31) / 25


def bowl() -> str:
    return f"M{n(12 + DX)} 8h20a14 14 0 0 1 0 28H{n(20 + DX)}v20h-8zM{n(20 + DX)} 16v12h12a6 6 0 0 0 0-12z"


def pins() -> str:
    def c(cx: float, cy: float, r: float = 1.6) -> str:
        return f"M{n(cx - r)} {n(cy)}a{r} {r} 0 1 0 {n(2 * r)} 0a{r} {r} 0 1 0 {n(-2 * r)} 0z"
    return "".join([c(x + DX - 1, 20) for x in (25, 29.5, 34)] + [c(x + DX - 1, 24.5) for x in (27.25, 31.75)])


def leg(y_top: float, y_bot: float, bits: list) -> str:
    pts = [(on(24, y_top), y_top), (on(33, y_top), y_top)]
    for ya, yb in bits:
        pts += [(on(33, ya), ya), (on(33, ya) + 4.5, ya), (on(33, yb) + 4.5, yb), (on(33, yb), yb)]
    pts += [(on(33, y_bot), y_bot), (on(24, y_bot), y_bot)]
    return "M" + "L".join(f"{n(x + DX)} {n(y)}" for x, y in pts) + "z"


GEOMETRY = {"viewBox": "0 0 64 64", "bowl": bowl(), "leg_ink": leg(31, JOIN, []), "pins": pins(),
            "blade": leg(JOIN, 56, BITS), "small_from_px": 32}


def body(ink: str, accent: str, small: bool = False, themed: bool = False) -> str:
    fi, fa = ('class="i"', 'class="a"') if themed else (f'fill="{ink}"', f'fill="{accent}"')
    g = GEOMETRY
    out = f'<path {fi} fill-rule="evenodd" d="{g["bowl"]}"/><path {fi} d="{g["leg_ink"]}"/>'
    if not small:
        out += f'<path {fi} d="{g["pins"]}"/>'
    return out + f'<path {fa} d="{g["blade"]}"/>'


def mark_svg(ink: str, accent: str, small: bool = False, themed: bool = False) -> str:
    style = ""
    if themed:
        style = (f"<style>.i{{fill:{INK}}}.a{{fill:{ACCENT}}}@media (prefers-color-scheme:dark)"
                 f"{{.i{{fill:{INK_DARK}}}.a{{fill:{ACCENT_DARK}}}}}</style>")
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-labelledby="t">'
            f'<title id="t">ReliKey</title>{style}{body(ink, accent, small, themed)}</svg>\n')


def main() -> None:
    out = ROOT / "mark"
    out.mkdir(exist_ok=True)
    for old in out.glob("*.svg"):
        old.unlink()
    (out / "geometry.json").write_text(json.dumps(GEOMETRY, indent=1) + "\n", encoding="utf-8")
    for small, suf in ((False, ""), (True, "-small")):
        (out / f"relikey-mark{suf}.svg").write_text(mark_svg("", "", small, themed=True), encoding="utf-8")
        (out / f"relikey-mark{suf}-light.svg").write_text(mark_svg(INK, ACCENT, small), encoding="utf-8")
        (out / f"relikey-mark{suf}-dark.svg").write_text(mark_svg(INK_DARK, ACCENT_DARK, small), encoding="utf-8")
        (out / f"relikey-mark{suf}-mono.svg").write_text(mark_svg("currentColor", "currentColor", small),
                                                          encoding="utf-8")
    for f in sorted(out.iterdir()):
        print(f"{f.relative_to(ROOT.parent)}  {f.stat().st_size} B")


if __name__ == "__main__":
    main()

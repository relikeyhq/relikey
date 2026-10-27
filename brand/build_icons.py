# SPDX-License-Identifier: EUPL-1.2
"""Build ReliKey's icons, lockup sources and social card source from the master geometry (brand/mark/geometry.json).

    uv run --with cairosvg,pillow python brand/build_icons.py

Writes brand/icons/: favicon.svg and favicon.ico (16, 32, 48) and the Android launcher layers from the SMALL mark (no
pins: shown at 48 px or less); apple-touch-icon.png (180), icon-192.png, icon-512.png, ios-1024.png and relikey-badge.svg
from the full mark. Writes the live-text sources of the lockups and the social card (brand/wordmark/*.src.svg,
brand/social/social.src.svg); outline them with brand-cycle's outline_text.py (README in BRAND.md). Same construction as
KeyClerk's brand/build_icons.py, so the two products' assets match.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import cairosvg
from PIL import Image

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "icons"
PLATE, WHITE, ORANGE_DARK, INK, ORANGE = "#17142b", "#ffffff", "#f0954f", "#17142b", "#c85d16"
G = json.loads((ROOT / "mark" / "geometry.json").read_text(encoding="utf-8"))
MOTTO = "Old systems. Modern keys."                                     # draft: the operator's sign-off pending
SUBLINE = "Passkeys, approvals and recorded sessions for systems that only know a password"


def geom(ink: str, accent: str, small: bool = False) -> str:
    out = f'<path fill="{ink}" fill-rule="evenodd" d="{G["bowl"]}"/><path fill="{ink}" d="{G["leg_ink"]}"/>'
    if not small:
        out += f'<path fill="{ink}" d="{G["pins"]}"/>'
    return out + f'<path fill="{accent}" d="{G["blade"]}"/>'


def mark(scale: float, ink: str, accent: str, small: bool = False) -> str:
    """The mark centred on (32, 32) of a 64 viewBox at `scale` of its master size."""
    return f'<g transform="translate(32 32) scale({scale}) translate(-32 -32)">{geom(ink, accent, small)}</g>'


def svg(body: str, plate: str | None = None, rx: float = 0, edge: bool = False) -> str:
    """edge: a faint light rim inside a rounded plate, so it separates from very dark grounds (GitHub dark, tabs)."""
    bg = f'<rect width="64" height="64" rx="{rx}" fill="{plate}"/>' if plate else ""
    if plate and edge:
        bg += (f'<rect x=".5" y=".5" width="63" height="63" rx="{max(rx - .5, 0)}" fill="none" '
               'stroke="#fff" stroke-opacity=".2" stroke-width="1"/>')
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-labelledby="t">'
            f'<title id="t">ReliKey</title>{bg}{body}</svg>')


def png(src: str, size: int) -> Image.Image:
    return Image.open(io.BytesIO(cairosvg.svg2png(bytestring=src.encode(), output_width=size, output_height=size)))


def lockups_and_card() -> None:
    (ROOT / "wordmark").mkdir(exist_ok=True)
    (ROOT / "social").mkdir(exist_ok=True)
    for name, ink, acc in (("light", INK, ORANGE), ("dark", WHITE, ORANGE_DARK)):
        (ROOT / "wordmark" / f"lockup-{name}.src.svg").write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 222 64" role="img" aria-labelledby="t">'
            '<title id="t">ReliKey</title>'
            f'<g transform="translate(0 2) scale(.94)">{geom(ink, acc)}</g>'
            f'<text x="62" y="44" font-family="IBM Plex Sans SemiBold" font-size="34" letter-spacing="-0.4" fill="{ink}">'
            "ReliKey</text></svg>\n", encoding="utf-8")
    (ROOT / "social" / "social.src.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" role="img" aria-labelledby="t">'
        f'<title id="t">ReliKey: {MOTTO}</title>'
        '<defs><radialGradient id="g" cx="50%" cy="45%" r="75%"><stop offset="0" stop-color="#1d2338"/>'
        '<stop offset="1" stop-color="#0b0e17"/></radialGradient></defs><rect width="1280" height="640" fill="url(#g)"/>'
        f'<g transform="translate(150 150) scale(3.6)">{geom(WHITE, ORANGE_DARK)}</g>'
        '<text x="400" y="304" font-family="IBM Plex Sans SemiBold" font-size="118" letter-spacing="-1.4" '
        'fill="#ffffff">ReliKey</text>'
        f'<text x="406" y="386" font-family="IBM Plex Sans" font-size="40" fill="#cfd4e0">{MOTTO}</text>'
        f'<text x="406" y="444" font-family="IBM Plex Sans" font-size="22" fill="#9aa3b5">{SUBLINE}</text>'
        "</svg>\n", encoding="utf-8")


def main() -> None:
    lockups_and_card()
    (OUT / "android").mkdir(parents=True, exist_ok=True)
    badge = svg(mark(0.76, WHITE, ORANGE_DARK), PLATE, rx=14, edge=True)              # full mark on a rounded plate
    fav = svg(mark(0.86, WHITE, ORANGE_DARK, small=True), PLATE, rx=12, edge=True)   # small mark: reads at 16 px
    full = svg(mark(0.66, WHITE, ORANGE_DARK), PLATE)                                # full bleed: iOS, touch icon
    (OUT / "favicon.svg").write_text(fav, encoding="utf-8")
    (OUT / "relikey-badge.svg").write_text(badge, encoding="utf-8")
    png(fav, 48).save(OUT / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    png(full, 180).convert("RGB").save(OUT / "apple-touch-icon.png")
    png(full, 1024).convert("RGB").save(OUT / "ios-1024.png")
    png(badge, 192).save(OUT / "icon-192.png")
    png(badge, 512).save(OUT / "icon-512.png")
    # Android adaptive: 108 dp canvas, safe zone the central 66 dp; the mark is 48 of 64 units high, so this scale
    # makes it 95 % of the safe zone's height: 48 * scale / 64 = 0.95 * 66 / 108. Launchers show it small: no pins.
    safe = 0.95 * (66 / 108) * (64 / 48)
    png(svg(mark(safe, WHITE, ORANGE_DARK, small=True)), 432).save(OUT / "android" / "ic_launcher_foreground.png")
    png(svg("", PLATE), 432).convert("RGB").save(OUT / "android" / "ic_launcher_background.png")
    png(svg(mark(safe, WHITE, WHITE, small=True)), 432).save(OUT / "android" / "ic_launcher_monochrome.png")
    for f in sorted(OUT.rglob("*")):
        if f.is_file():
            print(f"{f.relative_to(ROOT)}  {f.stat().st_size} B")


if __name__ == "__main__":
    main()

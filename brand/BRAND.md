# ReliKey brand

Status: mark chosen (operator, 2026-10-24); mark, lockups, icons and social card built. The motto is a draft awaiting the
operator's sign-off.

## Brief
- **What it is:** ReliKey puts passkey sign-in, approved time-boxed access and recorded sessions in front of systems that
  only know a password, with an edge that keeps working when the site is cut off: old systems protected with modern
  identity, credential and access management.
- **Audience:** OT and plant security leads, engineering managers and IT/OT integrators at European industrial sites and
  public bodies; auditors; the equipment vendors' engineers who sign in through it.
- **Three attributes:** dependable (the plant keeps running, access fails closed, offline is normal), plainspoken (made
  for the plant floor: no hype, no cyber theatre), respectful of the old (the legacy system stays as it is; ReliKey
  wraps it, it does not replace it).
- **Must not look like:**
  1. a shield, padlock or fortress (the category's default);
  2. the violet, blue and teal cluster of the OT remote-access vendors, or their lime, amber and magenta accents;
  3. KeyClerk's own mark: a sibling, not a copy (and no cloud or AI gradient).

## Narrative
Plants run on systems older than anyone who maintains them: controllers and consoles that only know a password, behind
serial ports and fixed accounts. ReliKey leaves them as they are and puts a modern key in front: a passkey, an approval,
a lease that ends by itself, every session recorded.

The mark is the R of ReliKey. Its bowl is a D, as a D-sub connector's shell is, and holds the connector's pins: the old
system. Its leg turns into a key blade in KeyClerk's orange: the modern access that reaches it.

## Motto (draft, the operator to confirm)
**Old systems. Modern keys.**
Subline: "Passkeys, approvals and recorded sessions for systems that only know a password".

## Family
KeyClerk (the governance engine inside ReliKey) has a finished brand (keyclerk `brand/BRAND.md`). ReliKey shares its
system so the two read as siblings stewarded by VDHome: the cool paper and ink, the orange accent (operator,
2026-10-24: one family accent; the marks tell the products apart), IBM Plex Sans, the filled-geometry construction (no
strokes, no masks, true knockouts) and the same icon set.

## Name
Relic plus key: an old system gets a modern key. Trade mark screen (TMview, 2026-10-23): no
live RELIKEY or close variant at EUIPO, BOIP or WIPO in classes 9 and 42. Availability (name_check.py, 2026-10-24):
PyPI free, GitHub free, .dev .be .eu free; .com (parked) and .app taken.

## Category map (category_scan.py, 2026-10-24)
| Product | Signals |
|---|---|
| Cyolo | amber #febe43, lime, teal #007e7f, dark navy-teal |
| Xona | slate teal #70a2ae, cream, maroon #92104f |
| Claroty | magenta #e20ab7 on black |
| Dispel, Tosi, Teleport | violet #7554da, #5226ef, #512fc9 (Tosi adds lime #e1f730 and coral) |
| CyberArk, Secomea, Ewon | blue (#8ad3de, #0d6efd, #1268b3) |
| Warpgate | steel blue #449fbe |
| JumpServer | near-black, teal-green #2b937c |
| BeyondTrust | orange (site refused the scan) |
| KeyClerk (sibling) | cool paper #f2f4f7, ink #17142b, orange #c85d16 |

Dominant: violet, blue and teal; shields, an X, abstract marks. Nobody uses a letterform or the legacy hardware itself.

## How the mark was found (concepts/)
- Round 1 (relic-bit, the-wrapper, r-bit, two-ages), two independent reviews (design on pixels, technical on SVG):
  r-bit the only ownable direction but read as a P; the-wrapper is Material's login icon; relic-bit too close to
  KeyClerk's key; two-ages collapsed at 24 px.
- Rounds 2 to 4 rebuilt the R: a diagonal leg (the only R that read at 16 px) as a key blade with two bits; a stencil
  gap tried for ink/accent separation (no dark-theme accent reached 3:1 against white ink).
- Operator: "a lock or a key enclosing something old to protect", then "about using modern ICAM to do so". Tried: a key
  whose bow holds a punch card, a padlock with a punch-card body (still the cliche), a smart card cut like a key, a key
  whose bow is a DE-9 connector, interlocked links, a connector in scan brackets. In use (concepts/inuse-*.png) the
  illustrative ones won in a lockup and lost at app-icon and favicon size.
- The R's bowl is a D, like a D-sub's shell: the connector's pins in the counter gave both halves (the legacy
  connector, the modern key) in one letter. Operator: the key must connect so it never reads as a P, and only the
  blade orange.

## The mark (master geometry: python brand/build_mark.py, writes mark/geometry.json)
Stem and bowl one evenodd path; the DE-9's pins (3 over 2, radius 1.6) in the counter, in ink; the leg ink from the
bowl to y 40 so the R's outline is unbroken, then the key blade in the accent with two bits standing 4.5 out (every
feature at least 4 units). The ink leg piece is its own path (in one evenodd path with the bowl the overlap cancels).
Files: mark/relikey-mark.svg (themed with prefers-color-scheme), -light, -dark (white ink), -mono (currentColor).
**Small mark** (32 px and below): the same without the pins, which would only grey the counter: relikey-mark-small*.svg.

## Palette (the family's, KeyClerk palette B)
| Role | Light | Dark |
|---|---|---|
| paper | #f2f4f7 | #0f1420 |
| ink | #17142b | #ffffff |
| accent (the key) | #c85d16 | #f0954f |
| orange text | #9a4a12 | #f0954f |

palette_check.py: ink on paper 16.27:1; accent on paper 3.79:1 (graphics, not small text); dark: white on #0f1420
18.4:1, accent 7.99:1. Accent against ink is 4.3:1 light but 2.3:1 dark, so the blade's separation from the ink leg in
dark mode rests on hue and shape, not luminance; at 16 px the R still reads (previews-master.png). The orange sits
near an amber warning (Delta E under 10 protan and deutan): status never by colour alone.

## Wordmark and lockup
IBM Plex Sans SemiBold (SIL Open Font Licence 1.1; latin subset covers nl and fr: e-acute, e-grave, e-circumflex,
e-diaeresis, i-diaeresis, c-cedilla, a-grave, u-grave, o-circumflex, oe, euro). Lockups outlined to paths, no font
ships: wordmark/relikey-lockup-light.svg and -dark.svg; live-text sources wordmark/lockup-*.src.svg (re-outline after
any change: brand-cycle's outline_text.py with the Plex TTFs from fontsource).

## Icons (uv run --with cairosvg,pillow python brand/build_icons.py)
favicon.svg and favicon.ico (16, 32, 48) from the small mark at 0.86 on the ink plate; relikey-badge.svg, icon-192.png,
icon-512.png with the full mark; apple-touch-icon.png (180) and ios-1024.png full bleed and opaque; android/ adaptive
foreground, background and monochrome (432 px = 108 dp, small mark at 95 % of the 66 dp safe zone).

## Social card
social/relikey-social.png (1280 x 640, from relikey-social.svg; source social.src.svg). GitHub has no API for the
social preview: upload it by hand in Settings, General, Social preview once the repository is public.

## Changelog
- 2026-10-24: brief, family rule, name status, category map; four concepts, two reviews; the R reworked over three
  rounds; palette options (operator: KeyClerk's orange, two bits).
- 2026-10-24: lock and ICAM angles explored at the operator's request; the R as a serial connector chosen, leg joined,
  only the blade orange; master, small mark, lockups, icons and social card built.

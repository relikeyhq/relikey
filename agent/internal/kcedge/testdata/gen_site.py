# SPDX-License-Identifier: EUPL-1.2
"""Site-statement vectors from the reference (keyclerk.edge_relay.site_statement, verify_site).

Run from a KeyClerk checkout at the pinned tag (KeyClerk on PYTHONPATH):  python gen_site.py > site.json
Fixed seed keys (site 21, node 22, another node 23, the officer 24); never use them for anything else. Each case
carries the reference's verdict: "ok" with the statement's fields, or "refused" with the reference's message, so the
agent's kcedge.VerifySite must agree on every one (edge protocol 1.5 section 14).
"""
import json
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import edge_relay as ER


def key(n):
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)


SITE, NODE, OTHER, OFFICER = key(21), key(22), key(23), key(24)
AT = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
EDGE = "plant-a"


def stmt(purpose="promotion", edge=EDGE, site=SITE, node=NODE, reason="node 1 is down, node 2 takes over",
         signers=None, change=None):
    obj = ER.site_statement(purpose, edge, E.public_hex(site), E.public_hex(node), AT, reason)
    if change:
        obj = change(dict(obj))
    s = E.cosign(signers[0] if signers else site, obj, ER.SITE_FORMAT)
    for k in (signers[1:] if signers else [node]):
        s = E.cosign(k, s, ER.SITE_FORMAT)
    return s


CASES = [
    ("a promotion signed by the site key and the node it names", stmt(), "promotion"),
    ("a provisional statement", stmt(purpose="provisional"), "provisional"),
    ("a provisional statement is not a promotion", stmt(purpose="provisional"), "promotion"),
    ("for another edge", stmt(edge="plant-b"), "promotion"),
    ("signed by the site key alone", stmt(signers=[SITE]), "promotion"),
    ("signed by the node alone", stmt(signers=[NODE]), "promotion"),
    ("signed by another node than it names", stmt(signers=[SITE, OTHER]), "promotion"),
    ("signed by another site key", stmt(site=OFFICER, signers=[OFFICER, NODE]), "promotion"),
    ("a third signature", stmt(signers=[SITE, NODE, OTHER]), "promotion"),
    ("a reason too short", stmt(reason="no"), "promotion"),
    ("an extra field", stmt(change=lambda o: {**o, "until": "2026-11-07T12:00:00Z"}), "promotion"),
]
out = []
for name, sealed, purpose in CASES:
    try:
        st = ER.verify_site(sealed, E.public_hex(SITE), EDGE, purpose)
        verdict = {"ok": True, "node_key": st["node_key"], "at": st["at"], "reason": st["reason"]}
    except ValueError as e:
        verdict = {"ok": False, "error": str(e)}
    out.append({"name": name, "purpose": purpose, "statement": sealed, "expected": verdict})
json.dump({"format": "relikey-site-vectors-v1", "source": "keyclerk.edge_relay.verify_site", "edge": EDGE,
           "site_key": E.public_hex(SITE), "node_key": E.public_hex(NODE), "cases": out}, sys.stdout, indent=1)
sys.stdout.write("\n")

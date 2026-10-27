"""Signed-request vectors from the reference (keyclerk.edge.sign_request, check_request).

Run from a KeyClerk checkout at the pinned tag (KeyClerk on PYTHONPATH):  python gen_requests.py > requests.json
Fixed seed key 5; never use it for anything else. "header" is what the reference signs for the fixed seconds and
nonce; Ed25519 is deterministic, so an agent must produce the same header byte for byte.
"""
import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E

KEY = Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
NONCE = "AAECAwQFBgcICQoLDA0ODxAR"   # 18 bytes, base64url without padding
CASES = [
    ("GET", "/api/v1/edge/bundle", b""),
    ("GET", "/api/v1/edge/bundle?serial=7", b""),
    ("POST", "/api/v1/edge/report", E.canonical({"applied_serial": 7, "attestation": {"profile": "basic"}, "drift": []})),
    ("post", "/api/v1/edge/incident", "{\"kind\":\"drift\",\"detail\":\"café\"}".encode()),
    ("GET", "/api/v1/edge/escrow/item%2F1", b""),
]
out = []
for method, path, body in CASES:
    header = E.sign_request(KEY, "edge-a", method, path, body, seconds=1792756800, nonce=NONCE)
    E.check_request(header, method.upper(), path, body, lambda _e: E.public_hex(KEY), E.Replay(), now=1792756800)
    out.append({"method": method, "path": path, "body": base64.b64encode(body).decode(), "header": header})
json.dump({"format": "relikey-request-vectors-v1", "source": "keyclerk.edge.sign_request", "edge": "edge-a",
           "seed": 5, "seconds": 1792756800, "nonce": NONCE, "public_key": E.public_hex(KEY), "cases": out},
          sys.stdout, indent=1)
sys.stdout.write("\n")

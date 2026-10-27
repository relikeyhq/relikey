# SPDX-License-Identifier: EUPL-1.2
"""deploy/edge/targets.py sends Warpgate's admin token only to the certificate install.py pinned (stack attack
2026-10-25, E8)."""
import datetime
import hashlib
import http.server
import importlib.util
import ssl
import threading
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_targets():
    spec = importlib.util.spec_from_file_location("edge_targets", ROOT / "deploy" / "edge" / "targets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def self_signed(tmp: Path) -> tuple[Path, Path, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))
    crt, k = tmp / "c.pem", tmp / "k.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return crt, k, cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def server(tmp_path):
    crt, key, der = self_signed(tmp_path)
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("X-Warpgate-Token"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"[]")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # the agent speaks 1.2 and later; no older fallback in tests
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}/", hashlib.sha256(der).hexdigest(), seen
    srv.shutdown()


def fetch(mod, url, pin):
    req = urllib.request.Request(url, headers={"X-Warpgate-Token": "the-admin-token"})
    with urllib.request.build_opener(mod.PinnedHTTPS(pin)).open(req, timeout=5) as r:
        return r.read()


def test_the_token_goes_to_the_pinned_certificate(server):
    url, pin, seen = server
    assert fetch(load_targets(), url, pin) == b"[]"
    assert seen == ["the-admin-token"]


def test_another_certificate_gets_no_token(server):
    url, pin, seen = server
    with pytest.raises(OSError):   # the pin refusal (ssl.SSLError), as urllib passes it on (URLError)
        fetch(load_targets(), url, "0" * 64)
    assert seen == []   # refused at the handshake: the request, and its token, never left

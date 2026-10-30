# SPDX-License-Identifier: EUPL-1.2
"""The edge installer's side of enrolment by code (deploy/edge/install.py, decision 0026 point 15): it reads the code,
presents the edge's key with proof of the secret over TLS that trusts only the CA the code pins, prints the fingerprint,
and never prints the code. The fleet's own end, with this code, is fleet/internal/fleet/enrolled_test.go."""
import base64
import datetime
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import ssl
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# One vector shared with fleet/internal/enrol (TestThePresentationMatchesTheInstallers): the same seed and code give
# the same key, signature and fingerprint in Go and in the installer.
SEED = hashlib.sha256(b"vector seed").digest()
CODE_SECRET = base64.b64encode(b"secret").decode()   # the vector's single-use secret, as Go's test spells it
VECTOR = {"fleet": "fleet-1", "url": "https://fleet.example/fleet/v1/enrol", "pin": "a" * 64, "anchor": "b" * 64,
          "slot": "slot-1", "secret": CODE_SECRET}
EDGE_PUB = "22a0fb81251d862fee728fa2344f6243bc00776bb0bf8e4d02df31714ed90b2f"
SIG = ("8bc7785c29059503fc16ffb0bce3a2bc4aea010546653899e053a5e6a933eb46"
       "1759f8ce1f9e6bd7c26df6f5cf799444c595f085f5ff04d822ad325eed88c607")
FINGERPRINT = "RGTV JDH4 4BF5 I5F6 MA7K UN6X G5CQ N4LJ CNJY NFMM NM7F I3HB Q7DQ"


def load():
    spec = importlib.util.spec_from_file_location("edge_install", ROOT / "deploy" / "edge" / "install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def code_text(fields: dict) -> str:
    raw = json.dumps(fields, separators=(",", ":")).encode()
    return "relikey-enrol-v1:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_the_presentation_and_fingerprint_match_the_fleets():
    m = load()
    p = m.presentation(VECTOR, SEED)
    assert (p["slot"], p["key"], p["secret"], p["sig"]) == ("slot-1", EDGE_PUB, CODE_SECRET, SIG)
    assert m.fingerprint(bytes.fromhex(EDGE_PUB)) == FINGERPRINT


def test_a_code_is_read_and_a_bad_one_refused_without_repeating_it():
    m = load()
    assert m.parse_code("\n" + code_text(VECTOR) + "\n") == VECTOR
    bad = [code_text({**VECTOR, "url": "http://fleet.example/fleet/v1/enrol"}), code_text({**VECTOR, "pin": "a"}),
           code_text({k: v for k, v in VECTOR.items() if k != "secret"}), "relikey-enrol-v1:!!", code_text(VECTOR)[1:]]
    for text in bad:
        with pytest.raises(ValueError) as e:
            m.parse_code(text)
        assert CODE_SECRET not in str(e.value) and text not in str(e.value)
        # the refusal says what to do next: check the file, or get a new code from the fleet page
        assert "exactly as the fleet page issued it" in str(e.value) and "for a new code" in str(e.value)


def test_enrolment_before_python_3_13_is_refused_and_says_why(monkeypatch, tmp_path):
    m = load()
    monkeypatch.setattr(m.sys, "version_info", (3, 12, 9))
    f = tmp_path / "code"
    f.write_text(code_text(VECTOR), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        m.enrol_by_code(str(f), SEED)
    assert "Python 3.13" in str(e.value) and "CA" in str(e.value) and CODE_SECRET not in str(e.value)


needs_313 = pytest.mark.skipif(sys.version_info < (3, 13), reason="enrolment by code needs Python 3.13's ssl")


@pytest.fixture
def fleet(tmp_path):
    """A fleet's enrolment route on loopback TLS (a leaf naming 127.0.0.1, sent with the fleet's CA): it checks the
    presentation as fleet/internal/enrol Accept does and answers 204, or the status a test sets. The code pins the
    CA; the state holds the leaf's hash for the test that pins it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fleet test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now - datetime.timedelta(hours=1))
          .not_valid_after(now + datetime.timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fleet")]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(2).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .sign(ca_key, hashes.SHA256()))
    crt, k = tmp_path / "c.pem", tmp_path / "k.pem"
    crt.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    state = {"status": 204, "seen": [],
             "leaf_pin": hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            p = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            commitment = hashlib.sha256(p["secret"].encode()).hexdigest()
            msg = "\n".join(["relikey-enrol-present-v1", "fleet-1", p["slot"], commitment]).encode()
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(p["key"])).verify(bytes.fromhex(p["sig"]), msg)
            state["seen"].append(p)
            self.send_response(state["status"])
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    srv.handle_error = lambda *a: None   # the pin probe connects and leaves without a request
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # what the installer's pinned client requires
    ctx.load_cert_chain(crt, k)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    code = {**VECTOR, "url": f"https://127.0.0.1:{srv.server_address[1]}/fleet/v1/enrol",
            "pin": hashlib.sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest()}
    yield code, state
    srv.shutdown()


@needs_313
def test_the_edge_presents_to_the_pinned_fleet_and_prints_only_the_fingerprint(fleet, tmp_path, capsys):
    code, state = fleet
    m = load()
    f = tmp_path / "code"
    f.write_text(code_text(code), encoding="utf-8")
    m.enrol_by_code(str(f), SEED)
    out = capsys.readouterr()
    assert FINGERPRINT in out.out
    assert code["secret"] not in out.out + out.err and code_text(code) not in out.out + out.err
    assert [p["key"] for p in state["seen"]] == [EDGE_PUB]


@needs_313
def test_another_certificate_gets_no_presentation(fleet):
    code, state = fleet
    with pytest.raises(SystemExit) as e:
        load().present({**code, "pin": "0" * 64}, SEED, timeout=5)
    assert "pinned certificate" in str(e.value)
    assert state["seen"] == []   # refused before the request: the secret never left


@needs_313
def test_a_pinned_leaf_gets_no_presentation(fleet):
    code, state = fleet
    with pytest.raises(SystemExit) as e:
        load().present({**code, "pin": state["leaf_pin"]}, SEED, timeout=5)
    assert "not a CA" in str(e.value)
    assert state["seen"] == []   # refused before the request: the secret never left


@needs_313
@pytest.mark.parametrize("status,says", [(409, "slot already taken"), (429, "try again in a minute"),
                                         (403, "refused the presentation")])
def test_the_fleets_refusals_are_shown(fleet, status, says):
    code, state = fleet
    state["status"] = status
    with pytest.raises(SystemExit) as e:
        load().present(code, SEED, timeout=5)
    assert says in str(e.value) and code["secret"] not in str(e.value)

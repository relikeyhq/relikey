# SPDX-License-Identifier: EUPL-1.2
"""The core installer writes enrolment by code (#74, decision 0026 points 14-33): install.py --fleet-host, in a
temporary directory with the container engine stubbed, leaves a fleet.json the fleet service and its page accept
(the keys their Go structs read), an enrolment URL on the edge-facing name, and a pin on the front's CA that the edge
installer's own pinned TLS accepts. A second run keeps the fleet's id; without a CA in front.crt enrolment stays off
and the installer says why."""
import datetime
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "deploy" / "core"
ARGS = ["--broker-host", "id.example", "--desk-host", "desk.example", "--edge-host", "edge.example",
        "--fleet-host", "fleet.example", "--fleet-officers", "ann,bob,cat", "--root", "Root Holder <root@example.org>",
        "--officer", "Sec Officer <sec@example.org>", "--yes", "--engine", "podman"]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def core(tmp_path, monkeypatch):
    """Runs install.py's main with deploy/secrets in tmp_path and every engine call answered by a stub; fleet_page.py,
    which install.py starts as a process, runs in this one. Returns run(*extra) -> the fleet.json written."""
    if importlib.util.find_spec("fcntl") is None:   # fleet_edge.py's lock; the configuration is what is tested here
        monkeypatch.setitem(sys.modules, "fcntl", types.SimpleNamespace(flock=lambda *a: None, LOCK_EX=2))
    monkeypatch.syspath_prepend(str(CORE))
    install = load("core_install", CORE / "install.py")
    page = load("core_fleet_page", CORE / "fleet_page.py")
    edge = sys.modules["fleet_edge"]
    secrets_dir = tmp_path / "deploy" / "secrets"
    (tmp_path / "agent" / "dist").mkdir(parents=True)   # the fleet's binaries are built: the page is set up
    for m in (install, page, edge):
        monkeypatch.setattr(m, "SECRETS", secrets_dir)
    monkeypatch.setattr(install, "ROOT", tmp_path)

    def run(cmd, **kw):
        if str(cmd[1]).endswith("fleet_page.py"):
            monkeypatch.setattr(sys, "argv", ["fleet_page.py"] + cmd[2:])
            assert page.main() == 0
        out = "ab" * 32 if "exec" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")
    monkeypatch.setattr(subprocess, "run", run)

    def go(*extra):
        monkeypatch.setattr(sys, "argv", ["install.py"] + ARGS + list(extra))
        assert install.main() == 0
        return json.loads((secrets_dir / "fleet" / "fleet.json").read_text(encoding="utf-8"))
    go.secrets, go.install, go.page = secrets_dir, install, page
    return go


def go_tags(path: str, struct: str) -> set:
    """The JSON keys a Go struct reads (the fleet decodes fleet.json with DisallowUnknownFields)."""
    body = re.search(r"type " + struct + r" struct \{(.*?)\n\}", (ROOT / path).read_text(encoding="utf-8"), re.S)
    return set(re.findall(r'json:"([a-z_]+)', body.group(1)))


def serve(crt: Path, key: Path):
    """The front, as far as TLS goes: front.crt and front.key on loopback, TLS 1.3."""
    srv = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    srv.handle_error = lambda *a: None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_a_fresh_core_writes_what_the_fleet_and_its_page_read(core):
    cfg = core()
    assert set(cfg) <= go_tags("fleet/cmd/relikey-fleet/main.go", "config")
    assert set(cfg["admin"]) == go_tags("fleet/cmd/relikey-fleet/main.go", "adminConfig")
    assert set(cfg["page"]) <= go_tags("fleet/internal/page/page.go", "Config")
    # main.go's load: the admin state is a file of its own, and the fleet has an id
    assert cfg["admin"]["state"] not in ("", cfg["state"]) and cfg["admin"]["fleet"]
    # the front routes the enrolment route on the edge-facing name (Caddyfile), on the port people and edges use
    assert cfg["page"]["enrol_url"] == "https://edge.example/fleet/v1/enrol"
    assert re.fullmatch(r"[0-9a-f]{64}", cfg["page"]["pin"])
    front = (core.secrets / "front.crt").read_text(encoding="utf-8")
    ca = (core.secrets / "front-ca.crt").read_text(encoding="utf-8")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    der = x509.load_pem_x509_certificate(ca.encode()).public_bytes(serialization.Encoding.DER)
    assert cfg["page"]["pin"] == hashlib.sha256(der).hexdigest()           # the CA (0026 point 27) ...
    assert cfg["page"]["pin"] != core.install.leaf_pin(front)               # ... not the leaf


@pytest.mark.skipif(sys.version_info < (3, 13), reason="a pinned CA needs the presented chain (Python 3.13)")
def test_the_edge_installer_trusts_the_front_by_the_pin_written(core):
    cfg = core()
    srv = serve(core.secrets / "front.crt", core.secrets / "front.key")
    try:
        edge = load("edge_install", ROOT / "deploy" / "edge" / "install.py")
        port = srv.server_address[1]
        ctx = edge.pinned_context("127.0.0.1", port, cfg["page"]["pin"])
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                             server_hostname="127.0.0.1") as t:
            assert t.version() == "TLSv1.3"
    finally:
        srv.shutdown()


def test_a_second_run_keeps_the_fleets_id_and_its_settings(core):
    first = core()
    assert core() == first   # never re-keyed in passing: a new fleet id would be a new fleet (point 30)


def test_a_local_ca_installed_before_the_chain_gets_it_and_enrolment(core):
    core()
    crt = core.secrets / "front.crt"
    leaf = crt.read_text(encoding="utf-8").split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    crt.write_text(leaf, encoding="utf-8")   # how a core installed before this change holds it
    cfg = core()
    assert crt.read_text(encoding="utf-8").startswith(leaf) and crt.read_text(encoding="utf-8").count("BEGIN") == 2
    assert cfg["page"]["pin"] != core.install.leaf_pin(leaf)


def leaf_only(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "id.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(n) for n in ("id.example", "desk.example", "edge.example", "fleet.example")]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(sans + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           False).sign(key, hashes.SHA256()))
    crt, k = tmp_path / "org.crt", tmp_path / "org.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return crt, k


def test_a_certificate_without_its_ca_leaves_enrolment_off_and_says_why(core, tmp_path, capsys):
    crt, key = leaf_only(tmp_path)
    cfg = core("--cert", str(crt), "--key", str(key))
    assert "admin" not in cfg and "pin" not in cfg["page"] and "enrol_url" not in cfg["page"]
    err = capsys.readouterr().err
    assert "enrolment by code is off" in err and "--cert the chain" in err and "fleet_page.py --host again" in err


def test_a_chain_in_the_wrong_order_is_refused(core):
    core()
    crt = (core.secrets / "front.crt").read_text(encoding="utf-8")
    leaf, ca = [c.strip("\n") + "\n-----END CERTIFICATE-----\n" for c in crt.split("-----END CERTIFICATE-----")[:2]]
    assert core.page.ca_pin(leaf + ca)[0]
    pin, why = core.page.ca_pin(ca + leaf)
    assert not pin and "not the CA that issued the first" in why

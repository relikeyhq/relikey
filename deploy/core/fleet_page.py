# SPDX-License-Identifier: EUPL-1.2
"""Give the fleet service its page (decision 0026 point 13): operators sign in at ReliKey's broker and see the
inventory on its own name, read-only. Run it on the core after install.py; install.py --fleet-host runs it itself.

    python deploy/core/fleet_page.py --host fleet.example [--engine docker] [--lab]

It makes the fleet's client secret (deploy/secrets/fleet/page.secret, readable by the fleet's uid only), the broker
client relikey-fleet (confidential, PKCE, a client role fleet-operator in the ID token, back-channel logout to the
pod's loopback), fleet.json's page section, and the front's site for the name, which proxies only the page's routes.
With it, enrolment by code (0026 points 14-33): fleet.json's admin section, written once and kept, and the page's
enrol_url (the edge-facing name) and pin_ca_file (deploy/secrets/fleet/pin-ca.crt: the CA that issued the front's
certificate, the second one in front.crt, which the codes pin); without that CA in front.crt it says why and leaves
enrolment off. The front's certificate must name the host: install.py --fleet-host puts it in a local CA's
certificate; with --cert, the organisation's certificate must carry it. Who may see the page: the client role
fleet-operator, granted at the broker (python deploy/core/fleet_page.py --grant <username>) or by the clerk's
governance.
"""
import argparse
import hashlib
import os
import re
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRETS = ROOT / "deploy" / "secrets"
CORE = ROOT / "deploy" / "core"
FLEET_UID = 10002
PAGE_PORT = 8094
ADMIN_STATE = "/var/lib/relikey-fleet/admin.json"   # the fleet's volume (compose.yaml), beside the inventory's state
PIN_CA = "/etc/relikey/fleet/pin-ca.crt"   # deploy/secrets/fleet/pin-ca.crt, mounted read-only (compose.yaml)
HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
sys.path.insert(0, str(CORE))
from fleet_edge import save   # noqa: E402  the same locked, atomic write as the known edges
from install import BUSYBOX   # noqa: E402  the busybox Dockerfile.fleet pins, by digest


def env(name: str) -> str:
    for line in (SECRETS / "core.env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    sys.exit(f"{name} missing from deploy/secrets/core.env: run deploy/core/install.py first")


def names_in(cert_pem: str) -> set:
    from cryptography import x509
    c = x509.load_pem_x509_certificates(cert_pem.encode())[0]
    try:
        return {n.lower() for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                .get_values_for_type(x509.DNSName)}
    except x509.ExtensionNotFound:
        return set()


def issuing_ca(front_crt: str) -> tuple[str, str]:
    """What an enrolment code pins (0026 point 27): the CA certificate that issued the front's certificate, as the
    front presents it (front.crt holds the leaf, then its CA); the fleet takes its sha256 as the pin. Pinning the CA,
    not the leaf, keeps codes valid across a leaf's renewal. Returns (its PEM, "") or ("", why and what to do)."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    again = "then run deploy/core/fleet_page.py --host again"
    certs = x509.load_pem_x509_certificates(front_crt.encode())
    if len(certs) < 2:
        return "", ("deploy/secrets/front.crt holds only the front's own certificate, so an edge cannot see the CA a "
                    "code pins. Give install.py --cert the chain (the certificate, then the CA that issued it), "
                    + again)
    try:
        certs[0].verify_directly_issued_by(certs[1])
        ca = certs[1].extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        ca = False
    if not ca:
        return "", ("the second certificate in deploy/secrets/front.crt is not the CA that issued the first. Put the "
                    "front's certificate first and its issuing CA second, " + again)
    return certs[1].public_bytes(serialization.Encoding.PEM).decode(), ""


def pin_of(pem_text: str) -> str:
    """The pin as the fleet computes it from pin_ca_file: the sha256 of the certificate's DER."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    der = x509.load_pem_x509_certificate(pem_text.encode()).public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def enrolment(cfg: dict, before: dict, url: str, pin: str, old_pin: str, why: str) -> str:
    """Enrolment by code (0026 points 14-33) in fleet.json: the admin section (the officer registry, the slots and
    the evidence log, in a state file of its own) and the page's enrol_url and pin_ca_file, from which every code
    gets its pin. Only with a CA: without one the page hands out no code. An admin section already there is kept as
    it is: a new fleet id would make a new fleet (point 30), so a second run never re-keys one. Returns what to tell.
    pin is that of the CA now written to pin_ca_file ("" for none), old_pin that of the one it replaced."""
    if not pin:
        if "admin" in cfg and before.get("pin_ca_file"):
            # the fleet refuses an admin section without both: keep the last ones, so it still starts
            cfg["page"]["enrol_url"], cfg["page"]["pin_ca_file"] = before.get("enrol_url"), before["pin_ca_file"]
            return (f"enrolment by code keeps its last CA, but the front no longer presents a usable one, so new "
                    f"codes fail at the edge: {why}")
        kept = (" (the fleet's id and its state are kept, but the fleet will not start without pin_ca_file)"
                if "admin" in cfg else "")
        return f"enrolment by code is off{kept}: {why}"
    cfg.setdefault("admin", {"state": ADMIN_STATE, "fleet": str(uuid.uuid4())})
    cfg["page"]["enrol_url"], cfg["page"]["pin_ca_file"] = url, PIN_CA
    said = f"enrolment by code: edges present at {url}; codes pin the front's CA, sha256 {pin}"
    if old_pin not in ("", pin):
        said += (f". The pin changed from {old_pin}: codes opened before it fail at the edge; open new slots "
                 "for those edges")
    return said


def compose(o) -> list:
    c = [o.engine, "compose", "--env-file", str(SECRETS / "core.env"), "-f", str(CORE / "compose.yaml")]
    return c + (["-f", str(CORE / "compose.lab.yaml")] if o.lab else [])


def page(o) -> None:
    host = o.host.lower()
    if not HOST.fullmatch(host):
        sys.exit("--host: a DNS name")
    if host in {env("BROKER_HOST"), env("DESK_HOST"), env("EDGE_HOST")}:
        sys.exit("--host: a name of its own, not the broker's, the desk's or the edge-facing one (0026 point 13)")
    if host not in names_in((SECRETS / "front.crt").read_text(encoding="utf-8")):
        sys.exit(f"the front's certificate does not name {host}: reissue it with that name (a local CA: install.py "
                 "--fleet-host on a fresh install), then run this again")
    port = env("BROKER_URL").rsplit(":", 1)[-1] if env("BROKER_URL").count(":") == 2 else "443"
    suffix = "" if port == "443" else f":{port}"
    page_url = f"https://{host}{suffix}"
    d = SECRETS / "fleet"
    secret = d / "page.secret"
    if not secret.exists():   # 0600 from the start: never readable by others, not even for a moment
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(secrets.token_urlsafe(32) + "\n")
    ca = SECRETS / ("front-ca.crt" if (SECRETS / "front-ca.crt").exists() else "front.crt")
    (d / "front-ca.crt").write_text(ca.read_text(encoding="utf-8"), encoding="utf-8")
    (d / "front-ca.crt").chmod(0o644)
    # The secret: the fleet's uid alone. Under rootful docker as a user, the pinned busybox sets it (install.py's way).
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(secret, FLEET_UID, FLEET_UID)
        secret.chmod(0o400)
    elif o.engine == "docker":
        subprocess.run([o.engine, "run", "--rm", "-v", f"{d}:/d", BUSYBOX, "sh", "-c",
                        f"chown {FLEET_UID}:{FLEET_UID} /d/page.secret && chmod 0400 /d/page.secret"], check=True)
    else:
        print(f"note: deploy/secrets/fleet/page.secret needs owner {FLEET_UID}, mode 0400 (podman unshare chown, or "
              "run as root)", file=sys.stderr)
    subprocess.run(compose(o) + ["run", "--rm", "--no-deps", "-T", "setup", "fleet", page_url],
                   input=_read_secret(o, d), text=True, check=True)
    ca_pem, why = issuing_ca((SECRETS / "front.crt").read_text(encoding="utf-8"))
    pin_file, pin, old_pin = d / "pin-ca.crt", "", ""
    if ca_pem:   # a certificate, no secret: the fleet's uid reads it as "other", like front-ca.crt
        old_pin = pin_of(pin_file.read_text(encoding="utf-8")) if pin_file.exists() else ""
        pin_file.write_text(ca_pem, encoding="utf-8")
        pin_file.chmod(0o644)
        pin = pin_of(ca_pem)
    said = []

    def write(cfg):
        # the first officers (0026 points 16, 30): named here, kept across reruns that do not name them
        before = cfg.get("page", {})
        officers = o.officers or before.get("officers", [])
        cfg["page"] = {
            "listen": f"127.0.0.1:{PAGE_PORT}", "issuer": f"{env('BROKER_URL')}/realms/{env('REALM')}",
            "client_id": "relikey-fleet", "secret_file": "/etc/relikey/fleet/page.secret",
            "redirect_url": f"{page_url}/callback", "role": "fleet-operator",
            "ca_file": "/etc/relikey/fleet/front-ca.crt", "front": "127.0.0.1:8443", "officers": officers}
        # edges present on the edge-facing name, where the front routes /fleet/v1/enrol (Caddyfile)
        said[:] = [enrolment(cfg, before, f"https://{env('EDGE_HOST')}{suffix}/fleet/v1/enrol", pin, old_pin, why)]
    save(write)
    sites = SECRETS / "sites"
    sites.mkdir(exist_ok=True)
    (sites / "fleet.caddy").write_text(
        f"# The fleet page (0026 point 13), written by deploy/core/fleet_page.py: only its routes.\n"
        f"https://{host}:8443 {{\n\timport tls_core\n"
        f"\t@page path / /callback /logout /slots /officer/begin /officer/finish /anchor/begin /anchor/sign "
        f"/activate/begin /activate/sign\n"
        f"\thandle @page {{\n"
        f"\t\treverse_proxy 127.0.0.1:{PAGE_PORT} {{\n\t\t\theader_up Host 127.0.0.1:{PAGE_PORT}\n\t\t}}\n\t}}\n"
        f"\thandle {{\n\t\trespond 404\n\t}}\n}}\n", encoding="utf-8")
    (sites / "fleet.caddy").chmod(0o644)
    # The front has no admin API (Caddyfile: admin off), so no reload: a restart reads the new site file.
    subprocess.run(compose(o) + ["restart", "front"], check=True)
    subprocess.run(compose(o) + ["restart", "fleet"], check=True)
    print(f"fleet page: {page_url}/ for accounts holding the client role fleet-operator on relikey-fleet")
    print(*said, file=sys.stdout if pin else sys.stderr)


def _read_secret(o, d: Path) -> str:
    """The secret for the setup container's stdin: after the chown only the fleet's uid reads the file, so the
    pinned busybox prints it into the pipe (never to the terminal or argv)."""
    try:
        return (d / "page.secret").read_text(encoding="utf-8")
    except PermissionError:
        return subprocess.run([o.engine, "run", "--rm", "-v", f"{d}:/d:ro", BUSYBOX, "cat",
                               "/d/page.secret"], capture_output=True, text=True, check=True).stdout


def officer_list(v: str) -> list[str]:
    names = [n.strip() for n in v.split(",") if n.strip()]
    if len(names) < 3 or len(set(names)) != len(names) or not all(re.fullmatch(r"[a-z0-9][a-z0-9._@-]{0,254}", n) for n in names):
        raise argparse.ArgumentTypeError("at least three distinct broker usernames, comma-separated")
    return names


def main() -> int:
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--host", help="the page's own name, e.g. fleet.example")
    g.add_argument("--grant", metavar="USERNAME", help="grant the client role fleet-operator to this broker account")
    a.add_argument("--revoke", action="store_true", help="with --grant: take the role away instead")
    a.add_argument("--officers", type=officer_list, metavar="U1,U2,U3",
                   help="with --host: the first officers' broker usernames, at least three; each registers a passkey "
                        "on the page and signs the anchor (0026 points 16, 30)")
    a.add_argument("--engine", default="podman")
    a.add_argument("--lab", action="store_true", help="the core was installed with --lab")
    o = a.parse_args()
    if not (SECRETS / "core.env").exists():
        sys.exit("no deploy/secrets/core.env: run deploy/core/install.py first")
    if o.grant:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._@-]{0,254}", o.grant):
            sys.exit("--grant: a broker username")
        subprocess.run(compose(o) + ["run", "--rm", "--no-deps", "-T", "setup", "fleet-revoke" if o.revoke else
                                     "fleet-grant", o.grant], check=True)
        return 0
    page(o)
    return 0


if __name__ == "__main__":
    sys.exit(main())

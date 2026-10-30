# SPDX-License-Identifier: EUPL-1.2
"""Give the fleet service its page (decision 0026 point 13): operators sign in at ReliKey's broker and see the
inventory on its own name, read-only. Run it on the core after install.py; install.py --fleet-host runs it itself.

    python deploy/core/fleet_page.py --host fleet.example [--engine docker] [--lab]

It makes the fleet's client secret (deploy/secrets/fleet/page.secret, readable by the fleet's uid only), the broker
client relikey-fleet (confidential, PKCE, a client role fleet-operator in the ID token, back-channel logout to the
pod's loopback), fleet.json's page section, and the front's site for the name, which proxies only /, /callback and
/logout. The front's certificate must name the host: install.py --fleet-host puts it in a local CA's certificate;
with --cert, the organisation's certificate must carry it. Who may see the page: the client role fleet-operator,
granted at the broker (python deploy/core/fleet_page.py --grant <username>) or by the clerk's governance.
"""
import argparse
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRETS = ROOT / "deploy" / "secrets"
CORE = ROOT / "deploy" / "core"
FLEET_UID = 10002
PAGE_PORT = 8094
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
    def write(cfg):
        # the first officers (0026 points 16, 30): named here, kept across reruns that do not name them
        officers = o.officers or cfg.get("page", {}).get("officers", [])
        cfg["page"] = {
            "listen": f"127.0.0.1:{PAGE_PORT}", "issuer": f"{env('BROKER_URL')}/realms/{env('REALM')}",
            "client_id": "relikey-fleet", "secret_file": "/etc/relikey/fleet/page.secret",
            "redirect_url": f"{page_url}/callback", "role": "fleet-operator",
            "ca_file": "/etc/relikey/fleet/front-ca.crt", "front": "127.0.0.1:8443", "officers": officers}
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

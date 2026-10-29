# SPDX-License-Identifier: EUPL-1.2
"""Prepare a ReliKey edge pod: secrets, the enrolment key, Warpgate's first setup and the agent's configuration.

    python deploy/edge/install.py --edge plant-a --desk https://keyclerk.example --desk-ca desk-ca.pem \
        --bundle-key <64 hex, read out by the desk operator> --officer-key <64 hex> [--engine podman] \
        [--sso-issuer https://id.example/realms/relikey --sso-secret-file warpgate-plant-a.secret [--sso-ca front-ca.crt]] [--lab]

Writes deploy/secrets/ (git-ignored, files 0600 owned by the agent's uid 65532), runs Warpgate's unattended setup
once in its volume, and prints the enrolment key to enrol at the desk. Then: `podman compose -f deploy/edge/compose.yaml
up -d` (with `--lab`, also `-f deploy/edge/compose.lab.yaml`). Nothing here is secret-free: never commit deploy/secrets/.

With --sso-issuer, Warpgate signs people in at the core's broker (decision 0010) through the client the core made
for this edge (deploy/core/add_edge.py): authentication only. No roles claim is read; role_mappings holds one key no
identity provider sends, and Warpgate creates no users (the agent provisions them from signed leases). --sso-ca is
for a broker behind the core's local CA. SSL_CERT_FILE is process-wide in Warpgate (its rustls native roots, OpenSSL
for RDP, the S3 client for recordings), so it names a bundle of the public roots plus that CA, never the CA alone:
the public roots come from --ca-bundle, or certifi, or the host's bundle.

With --enrol-code-file (decision 0026 point 15), the edge also enrols into its fleet: the file holds the one-time code
from the fleet page (carried as a QR code or on a USB stick, never typed, never on the command line). The installer
presents this edge's enrolment key with proof of the code's secret, over TLS that trusts only the fleet's CA the
code pins (this needs Python 3.13 or later), and prints the key's fingerprint for whoever reads it to the approving
officer. Nothing is admitted until an officer approves with their passkey. To present again for an installed edge (the fleet was unreachable, say):

    python deploy/edge/install.py enrol --code-file <the code's file>
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
SECRETS = ROOT / "deploy" / "secrets"
COMPOSE = ROOT / "deploy" / "edge" / "compose.yaml"
COMPOSE_LAB = ROOT / "deploy" / "edge" / "compose.lab.yaml"
AGENT_UID = 65532


def write(name: str, text: str, owner: int | None = AGENT_UID) -> Path:
    p = SECRETS / name
    p.unlink(missing_ok=True)   # replaced, not opened: a re-run cannot write a file fix_owners gave the agent
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if owner is not None and hasattr(os, "chown"):
        try:
            os.chown(p, owner, owner)
        except PermissionError:
            pass                # fix_owners: busybox under rootful docker, a note otherwise
    return p


AGENT_READS = ("agent.json", "enrolment.key", "warpgate.token")   # compose.yaml: mounted into the agent (AGENT_UID)
FRONT_READS = ("front.key",)   # the front's key: root in the front's container (Caddy's image runs as root, no caps)


def fix_owners(engine: str) -> None:
    """Rootful docker run by a non-root user: the agent (AGENT_UID) cannot read the 0600 files the installing user
    owns, and chown needs root (full-stack run 2; the core's install.py has the same pass). The pinned busybox sets
    them; rootless podman maps the user to the container's root instead."""
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return                  # root: write() set the owners itself
    if engine != "docker":
        print(f"note: {', '.join(AGENT_READS)} in {SECRETS} need owner {AGENT_UID}: rootless podman's subuid mapping"
              " (podman unshare chown), or run as root", file=sys.stderr)
        return
    script = " && ".join([f"chown {AGENT_UID}:{AGENT_UID} /s/{f}" for f in AGENT_READS] +
                         [f"chown 0:0 /s/{f} && chmod 600 /s/{f}" for f in FRONT_READS])
    subprocess.run([engine, "run", "--rm", "-v", f"{SECRETS}:/s", "docker.io/library/busybox:1.37.0", "sh", "-c", script],
                   check=True)


def public_roots(given: str | None) -> bytes:
    """The public roots Warpgate keeps when SSL_CERT_FILE adds the core's CA: a bundle without them would silently
    break its other TLS clients (recording upload, public HTTPS targets, a public identity provider)."""
    paths = [given] if given else []
    try:
        import certifi
        paths.append(certifi.where())
    except ImportError:
        pass
    paths += ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"]
    for p in paths:
        if p and Path(p).is_file():
            data = Path(p).read_bytes()
            if data.count(b"BEGIN CERTIFICATE") >= 50:   # a real public set, not a stray single certificate
                return data
            if given:
                sys.exit(f"--ca-bundle {p}: fewer than 50 certificates, not a public root set")
    sys.exit("--sso-ca needs the public roots beside it: pass --ca-bundle, or install certifi")


CODE_PREFIX = "relikey-enrol-v1:"
PRESENT_CONTEXT = "relikey-enrol-present-v1"   # fleet/internal/enrol: the edge's signature over fleet, slot, commitment
CODE_NEXT_STEP = (f"check that the file holds the code exactly as the fleet page issued it (one line starting "
                  f"{CODE_PREFIX}), or ask the fleet's operator to open a new slot on the fleet page for a new code")


def parse_code(text: str) -> dict:
    """The enrolment code as the fleet page gives it (fleet/internal/enrol ParseCode). Errors never repeat the code:
    its secret is single-use and is never logged or printed. They say what to do next: the file may be damaged in
    transit, or hold something else; a new code comes from the fleet page."""
    text = text.strip()
    try:
        if not text.startswith(CODE_PREFIX):
            raise ValueError
        raw = text[len(CODE_PREFIX):]
        code = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, TypeError):
        raise ValueError(f"not a ReliKey enrolment code: {CODE_NEXT_STEP}") from None
    if not isinstance(code, dict):
        raise ValueError(f"not a ReliKey enrolment code: {CODE_NEXT_STEP}")
    fields = {k: code.get(k) for k in ("fleet", "url", "pin", "anchor", "slot", "secret")}
    if (not all(isinstance(v, str) and v for v in fields.values()) or not fields["url"].startswith("https://")
            or len(fields["pin"]) != 64 or len(fields["anchor"]) != 64):
        raise ValueError(f"the enrolment code lacks the fleet's address, pin, anchor, slot or secret: {CODE_NEXT_STEP}")
    return fields


def fingerprint(key: bytes) -> str:
    """How the edge's screen shows its key (fleet/internal/enrol Fingerprint): base32 of sha256, in groups of four."""
    enc = base64.b32encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    return " ".join(enc[i:i + 4] for i in range(0, len(enc), 4))


def presentation(code: dict, seed: bytes) -> dict:
    """The edge's key, the code's secret, and the key's signature over the fleet, the slot and the secret's
    commitment (proof of possession, 0026 point 24)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    commitment = hashlib.sha256(code["secret"].encode()).hexdigest()
    msg = "\n".join([PRESENT_CONTEXT, code["fleet"], code["slot"], commitment]).encode()
    return {"slot": code["slot"], "key": priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "secret": code["secret"], "sig": priv.sign(msg).hex()}


def require_ca_pin_support() -> None:
    """Enrolment by code needs Python 3.13: the code pins the fleet's CA (0026 point 27), and only from 3.13 does ssl
    give the chain the fleet presents, where that CA is found; before it, only the leaf can be read."""
    if sys.version_info < (3, 13):
        raise SystemExit(f"enrolment by code needs Python 3.13 or later (this is {sys.version.split()[0]}): the code "
                         "pins the fleet's CA, and only Python 3.13's ssl reads the chain the fleet presents to find "
                         "it. Install Python 3.13 or later (Debian 13 and current Raspberry Pi OS ship it), then run "
                         "the installer with it")


def is_ca(der: bytes) -> bool:
    from cryptography import x509
    try:
        return x509.load_der_x509_certificate(der).extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def pinned_context(host: str, port: int, pin: str, timeout: float = 20) -> ssl.SSLContext:
    """A TLS context that trusts only the CA the code pins (0026 point 27): the chain the fleet presents is read once,
    the certificate whose sha256 is the pin becomes the only root, and the real connection is verified against it,
    the host name included. A chain without it is refused, and so is a pinned certificate that is not a CA."""
    require_ca_pin_support()
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe.check_hostname, probe.verify_mode = False, ssl.CERT_NONE   # only to read the chain; nothing is sent
    probe.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with probe.wrap_socket(raw, server_hostname=host) as t:
            chain = t.get_unverified_chain()   # the whole chain the fleet sent (Python 3.13)
    for der in chain or []:   # DER bytes, as the fleet sent them
        if hashlib.sha256(der).hexdigest() == pin.lower():
            if not is_ca(der):
                raise ssl.SSLError("the code pins a certificate that is not a CA: a code pins the fleet's CA, never "
                                   "its leaf. Ask for a new code")
            ctx = ssl.create_default_context(cadata=der)   # this certificate alone; no system roots
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN   # the pinned certificate is the root, CA or not
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            return ctx
    raise ssl.SSLError("the fleet's certificate chain does not hold the pinned certificate: "
                       "not the fleet the code names")


def present(code: dict, seed: bytes, timeout: float = 20) -> str:
    """Presents this edge's key for its slot and returns the key's fingerprint. Raises SystemExit with what to do."""
    u = urlparse(code["url"])
    host, port = u.hostname, u.port or 443
    body = presentation(code, seed)
    try:
        ctx = pinned_context(host, port, code["pin"], timeout)
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        conn.request("POST", u.path or "/", body=json.dumps(body), headers={"Content-Type": "application/json"})
        status = conn.getresponse().status   # the body is not read: nothing the fleet says is acted on
        conn.close()
    except (OSError, ssl.SSLError) as e:
        raise SystemExit(f"enrolment: could not reach the fleet at {host}:{port} with its pinned certificate "
                         f"({e}). Check the address and the network, then: python deploy/edge/install.py enrol "
                         "--code-file ...") from None
    if status == 204:
        return fingerprint(bytes.fromhex(body["key"]))
    if status == 409:
        raise SystemExit("slot already taken: another key was presented for this slot. Tell the officer who opened it; "
                         "the fleet keeps the first key and shows the second")
    if status == 429:
        raise SystemExit("the fleet takes few enrolments a minute: try again in a minute (enrol --code-file ...)")
    raise SystemExit(f"the fleet refused the presentation ({status}): the code may have expired, been used, or not "
                     "be this fleet's. Ask for a new code; the reason is in the fleet's evidence log")


def enrol_by_code(code_file: str, seed: bytes) -> None:
    """Enrols this edge into the fleet its code names, and prints the fingerprint (shown only after presenting)."""
    require_ca_pin_support()
    code = parse_code(Path(code_file).read_text(encoding="utf-8"))
    fp = present(code, seed)
    print(f"enrolment into fleet {code['fleet']}: key presented. Read this fingerprint from this screen to the "
          f"approving officer, who types 16 of its characters (not the last 16) or all of it:\n  {fp}")


def enrol_main(argv: list[str]) -> int:
    a = argparse.ArgumentParser(prog="install.py enrol", description="present this installed edge's key to its fleet")
    a.add_argument("--code-file", required=True, help="the file holding the enrolment code from the fleet page")
    o = a.parse_args(argv)
    keyfile = SECRETS / "enrolment.key"
    try:
        seed = bytes.fromhex(keyfile.read_text().strip())
    except (OSError, ValueError):
        sys.exit(f"{keyfile}: no enrolment key to present; install the edge first (with --enrol-code-file)")
    try:
        enrol_by_code(o.code_file, seed)
    except (OSError, ValueError) as e:
        sys.exit(f"--code-file {o.code_file}: {e}")
    return 0


def main() -> int:
    if sys.argv[1:2] == ["enrol"]:
        return enrol_main(sys.argv[2:])
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--edge", required=True)
    a.add_argument("--desk", required=True, help="KeyClerk base URL (https)")
    a.add_argument("--desk-ca", help="PEM of the CA that signs the desk's certificate")
    a.add_argument("--desk-pin", help="or: the SHA-256 pin of the desk's certificate")
    a.add_argument("--bundle-key", required=True)
    a.add_argument("--officer-key", required=True)
    a.add_argument("--sso-provider", default="keycloak")
    a.add_argument("--engine", default="podman")
    a.add_argument("--enrolment-seed-file", help="reuse this enrolment seed (64 hex) instead of a new one")
    a.add_argument("--re-key", action="store_true", help="install over an installed edge: a new enrolment key (and admin "
                                                         "token), so the edge is cut off until it is enrolled again")
    a.add_argument("--sso-issuer", help="the core broker's realm, https://<broker>/realms/<realm>")
    a.add_argument("--sso-secret-file", help="this edge's client secret, from the core's add_edge.py")
    a.add_argument("--sso-client", help="the client id at the broker (default warpgate-<edge>)")
    a.add_argument("--sso-ca", help="PEM of the CA that signs the broker's certificate, when it is not a public one")
    a.add_argument("--ca-bundle", help="the public roots to keep beside --sso-ca (default: certifi, or the host's)")
    a.add_argument("--warpgate-url", help="the URL people reach this edge's Warpgate on, exactly as given to the core's "
                                          "add_edge.py: its host becomes Warpgate's external_host (sign-in return URL, "
                                          "cookie domain)")
    a.add_argument("--enrol-code-file", help="the fleet's one-time enrolment code, in a file (QR or USB stick, never "
                                             "typed): the edge also presents its key to its fleet (decision 0026)")
    a.add_argument("--lab", action="store_true", help="the pod on the host network (compose.lab.yaml), to reach a core "
                                                      "installed with --lab on the same box. Never in production")
    o = a.parse_args()
    if bool(o.desk_ca) == bool(o.desk_pin):
        sys.exit("give exactly one of --desk-ca and --desk-pin")
    if o.enrol_code_file:
        require_ca_pin_support()   # before anything is written, as the code below
        try:   # checked before anything is written: a code that cannot be read stops the install at its start
            parse_code(Path(o.enrol_code_file).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            sys.exit(f"--enrol-code-file {o.enrol_code_file}: {e}")
    if bool(o.sso_issuer) != bool(o.sso_secret_file) or (o.sso_ca and not o.sso_issuer):
        sys.exit("--sso-issuer and --sso-secret-file go together (and --sso-ca only with them)")
    if o.sso_issuer and not o.sso_issuer.startswith("https://"):
        sys.exit("--sso-issuer: https only")
    if o.sso_issuer and not o.warpgate_url:
        sys.exit("--sso-issuer needs --warpgate-url: Warpgate builds its sign-in return URL from it, and the broker only "
                 "accepts the URL the core registered with add_edge.py (--warpgate-url there); give the same one here")
    external_host = urlparse(o.warpgate_url).hostname if o.warpgate_url else o.edge   # full-stack run: never a bare id
    if (SECRETS / "enrolment.key").exists() and not (o.re_key or o.enrolment_seed_file):
        sys.exit(f"this edge is already installed ({SECRETS / 'enrolment.key'} exists). Running again would make a new "
                 "enrolment key, and the desk would refuse the edge until an officer enrols it again. To change the "
                 "agent's settings, edit agent.json; to re-key on purpose, add --re-key (full-stack run 2)")
    SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    bundle = public_roots(o.ca_bundle) + b"\n" + Path(o.sso_ca).read_bytes() if o.sso_ca else None
    write("warpgate.env", f"WARPGATE_ADMIN_TOKEN={token}\n" + ("SSL_CERT_FILE=/data/ca-bundle.pem\n" if bundle else ""),
          owner=None)
    write("warpgate.token", token + "\n")
    # compose reads every service's env_file and mounts even for `compose run warpgate` below: the front's files must
    # exist before it (placeholders, filled in once Warpgate's certificate exists; full-stack run 5).
    for name in ("front.env", "front.crt", "front.key", "warpgate.crt"):
        if not (SECRETS / name).exists():
            write(name, "", owner=None)
    write("lldap.env", f"LLDAP_JWT_SECRET={secrets.token_urlsafe(32)}\nLLDAP_KEY_SEED={secrets.token_urlsafe(32)}\n"
                       f"LLDAP_LDAP_USER_PASS={secrets.token_urlsafe(24)}\n", owner=None)
    seed = bytes.fromhex(Path(o.enrolment_seed_file).read_text().strip()) if o.enrolment_seed_file else secrets.token_bytes(32)
    write("enrolment.key", seed.hex() + "\n")
    # Warpgate's first setup, in its own volume; its certificate becomes the agent's pin.
    # The built-in admin's password goes through the environment, never argv (any local user reads /proc/*/cmdline:
    # stack attack 2026-10-25, E2). It is random and kept nowhere: the agent works with the admin token.
    run = [o.engine, "compose", "-f", str(COMPOSE), "run", "--rm", "--no-deps", "-e", "WARPGATE_ADMIN_PASSWORD",
           "warpgate"]
    subprocess.run(run + ["--config", "/data/warpgate.yaml", "unattended-setup", "--data-path", "/data",
                          "--http-port", "8888", "--ssh-port", "2222", "--record-sessions",
                          "--external-host", external_host],
                   check=True, env={**os.environ, "WARPGATE_ADMIN_PASSWORD": secrets.token_urlsafe(24)})
    # The Warpgate image holds only its binary (no shell, no cat): read the certificate from its volume with a
    # throwaway busybox, the same pinned one the agent image builds from.
    busybox = [o.engine, "run", "--rm", "-i", "-v", "relikey-edge_warpgate:/data", "docker.io/library/busybox:1.37.0"]
    der = subprocess.run(busybox + ["cat", "/data/tls.certificate.pem"], capture_output=True, check=False).stdout
    import yaml
    wg = yaml.safe_load(subprocess.run(busybox + ["cat", "/data/warpgate.yaml"], capture_output=True, check=True).stdout)
    # Warpgate's HTTPS on the pod's loopback only; the front publishes 8888 and refuses the admin paths (decision 0008
    # point 1, stack attack E6). Warpgate builds its return URLs with the external port, and takes the client's address
    # from the front's X-Forwarded headers (only pod members reach 127.0.0.1:8899).
    wg.setdefault("http", {}).update({"listen": "127.0.0.1:8899", "external_port": 8888, "trust_x_forwarded_headers": True})
    if o.sso_issuer:   # the broker's sign-in in Warpgate's configuration, in its volume (0600, like the rest of it)
        wg["sso_providers"] = [{"name": o.sso_provider, "label": "Sign in", "auto_create_users": False,
                                "provider": {"type": "custom", "client_id": o.sso_client or f"warpgate-{o.edge}",
                                             "client_secret": Path(o.sso_secret_file).read_text(encoding="utf-8").strip(),
                                             "issuer_url": o.sso_issuer.rstrip("/"), "scopes": ["openid", "email", "profile"],
                                             "role_mappings": {"relikey-no-idp-sends-this": "sso-unused"}}}]
    # busybox runs as root; give each file Warpgate's own owner (that of the key it generated), or under rootful
    # docker Warpgate (a non-root user) cannot read its 0600 config (found by the full-stack run; podman masked it)
    own = "chown $(stat -c %u:%g /data/tls.key.pem)"
    subprocess.run(busybox + ["sh", "-c", f"umask 077 && cat > /data/warpgate.yaml.new && {own} /data/warpgate.yaml.new"
                              " && mv /data/warpgate.yaml.new /data/warpgate.yaml"],
                   input=yaml.safe_dump(wg).encode(), check=True)
    if o.sso_issuer:
        if bundle:
            subprocess.run(busybox + ["sh", "-c", f"cat > /data/ca-bundle.pem && {own} /data/ca-bundle.pem"],
                           input=bundle, check=True)
    pin = ""
    if der:
        import base64
        import hashlib
        body = b"".join(ln for ln in der.splitlines() if ln and not ln.startswith(b"-----"))
        pin = hashlib.sha256(base64.b64decode(body)).hexdigest()
    if len(pin) != 64:
        sys.exit("could not read Warpgate's certificate from its volume: the agent would refuse to start without the pin")
    write("warpgate.pin", pin + "\n", owner=None)   # targets.py checks who answers before sending the token
    # The front: Warpgate's own certificate and key on the published port (people see what they saw before), and the
    # certificate as the only root the front trusts towards Warpgate, under the name it carries.
    key_pem = subprocess.run(busybox + ["cat", "/data/tls.key.pem"], capture_output=True, check=True).stdout.decode()
    write("front.crt", der.decode(), owner=None)
    write("front.key", key_pem, owner=None)
    write("warpgate.crt", der.decode(), owner=None)
    for f in ("front.crt", "warpgate.crt"):
        (SECRETS / f).chmod(0o644)   # public certificates: the front's root reads them without capabilities
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(der)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    cn = [a.value for a in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]
    tls_name = (names or cn or [""])[0]
    if not tls_name:
        sys.exit("Warpgate's certificate names no host: the front could not check it")
    write("front.env", f"WARPGATE_TLS_NAME={tls_name}\n", owner=None)
    keyclerk = {"url": o.desk}
    if o.desk_ca:
        keyclerk["ca_file"] = "/etc/relikey/desk-ca.pem"
        write("desk-ca.pem", Path(o.desk_ca).read_text(encoding="utf-8"))
    else:
        keyclerk["pin_sha256"] = o.desk_pin
    cfg = {"edge": o.edge, "mode": "enforce", "state_dir": "/var/lib/relikey",
           "enrolment_key_file": "/etc/relikey/enrolment.key",
           "pins": {"bundle_key": o.bundle_key, "officer_key": o.officer_key, "release_key": None},
           "clerk": keyclerk,                      # the clerk role (decision 0023)
           "bastion": {"kind": "warpgate", "url": "https://127.0.0.1:8899/@warpgate/admin/api", "token_file": "/etc/relikey/warpgate.token",
                        "pin_sha256": pin,
                        "sso_provider": o.sso_provider,
                        "governed_roles_file": "/etc/relikey/governed-roles.json"},   # targets.py fills it (finding 8)
           "fleet": {"url": o.desk},              # the fleet service's report route, on the front's edge-facing name (0026)
           "tick_seconds": 15, "pull_seconds": 60, "grace_seconds": 5}
    write("agent.json", json.dumps(cfg, indent=1) + "\n")
    governed = SECRETS / "governed-roles.json"
    if not governed.exists():   # created before compose mounts it (else a directory appears); targets.py fills it
        governed.write_text('{"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": 0, '
                            '"Resources": []}\n', encoding="utf-8")
        governed.chmod(0o644)   # not secret: role names; the agent reads it as "other"
    fix_owners(o.engine)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # only for printing the key
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    print(f"edge {o.edge}: enrol this enrolment key at the desk (officer and edge both sign the statement):\n  {pub}")
    if o.enrol_code_file:
        enrol_by_code(o.enrol_code_file, seed)
    files = [COMPOSE] + ([COMPOSE_LAB] if o.lab else [])
    print(f"then: {o.engine} compose {' '.join(f'-f {f.relative_to(ROOT).as_posix()}' for f in files)} up -d"
          + ("   (lab: without compose.lab.yaml the agent cannot reach the desk on the host's loopback)" if o.lab else ""))
    print("and:  python deploy/edge/targets.py deploy/edge/targets.yaml   (the roles leases name, the targets, their "
          "pinned host keys; see targets.example.yaml) - without it no lease can grant access")
    return 0


if __name__ == "__main__":
    sys.exit(main())

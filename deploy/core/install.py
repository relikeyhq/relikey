# SPDX-License-Identifier: EUPL-1.2
"""Prepare and start the ReliKey core pod (decision 0015): secrets, the front's certificate, the KeyClerk image, the
broker's realm and the desk's first records.

    python deploy/core/install.py --broker-host id.example --desk-host desk.example --edge-host edge.example \
        --root "Root Holder <root@example>" --officer "Officer Name <officer@example>" \
        --keyclerk-src ../keyclerk [--cert front.crt --key front.key] [--engine podman] [--lab]

Writes deploy/secrets/ (git-ignored; files 0600, those KeyClerk reads owned by its uid 10001), once: running it again
keeps every secret it finds there. Without --cert and --key it makes a local CA and a leaf for the three names
(front.crt holds the leaf, then the CA). With --fleet-host it also gives the fleet its page and enrolment by code
(fleet_page.py): fleet.json's admin section, once, and the page's enrol_url and pin_ca_file (the CA after the leaf).
Builds KeyClerk from its tag with KeyClerk's own Containerfile, starts the broker, sets up the realm (realm.py), then
starts the rest and prints what an edge's install.py needs: the desk's certificate pin (or the CA) and its bundle key.
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRETS = ROOT / "deploy" / "secrets"
CORE = ROOT / "deploy" / "core"
KEYCLERK_VERSION = "0.26.3"                      # model/components.yaml, id clerk
KEYCLERK_COMMIT = "cfc57939f3d88a7e44d62674465734d2c2f6f79c"   # the signed tag v0.26.3 on github.com/keyclerk/keyclerk
KEYCLERK_UID = 10001
HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def pinned_busybox(image_file: Path) -> str:
    """The busybox an image file builds from, with its digest: the helper containers below run that same reference,
    so a moved tag cannot change what runs with the secrets directory mounted, and Dependabot's update of the image
    file updates them too."""
    m = re.search(r"^FROM\s+(\S+/busybox:\S+@sha256:[0-9a-f]{64})", image_file.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit(f"{image_file}: no busybox base pinned by digest")
    return m.group(1)


BUSYBOX = pinned_busybox(CORE / "Dockerfile.fleet")   # also fleet_page.py's helper


CLERK_READS = ("keyclerk-writer.secret", "keyclerk-reader.secret", "relikey-setup.secret", "keyclerk-mgmt.token", "records.key", "records.pub",
               "keyclerk-seed.yaml", "people.json")   # compose.yaml: mounted into containers running as KEYCLERK_UID


def write(name: str, text: str, owner: int | None = KEYCLERK_UID, keep: bool = True) -> Path:
    """Write a secret once: an existing file is kept, so a second run does not cut the core off its own database."""
    p = SECRETS / name
    if keep and p.exists():
        return p
    p.unlink(missing_ok=True)   # replaced, not opened: a file fix_owners gave a container's owner is not ours to write
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if owner is not None and hasattr(os, "chown"):
        try:
            os.chown(p, owner, owner)
        except PermissionError:
            pass                # fix_owners: busybox under rootful docker, a note otherwise
    return p


def fix_owners(engine: str) -> None:
    """Rootful docker run by a non-root user: every container drops all capabilities, so its root cannot read a 0600
    file the installing user owns, and the chowns above need root (full-stack run 2). The edge's pinned busybox sets
    them. The front's files go to root with the installer's group (0640), so the pin below can still be read."""
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return                  # root: write() set the owners itself
    if engine != "docker":
        print(f"note: the files KeyClerk reads in {SECRETS} need owner {KEYCLERK_UID}: rootless podman's subuid mapping"
              " (podman unshare chown), or run as root", file=sys.stderr)
        return
    todo = [(f, f"{KEYCLERK_UID}:{KEYCLERK_UID}", "600") for f in CLERK_READS if (SECRETS / f).exists()
            and f != "people.json"]
    todo += [("people.json", f"{KEYCLERK_UID}:{os.getgid()}", "640")]   # the operator reads the first passwords
    todo += [(f, f"0:{os.getgid()}", "640") for f in ("front.crt", "front.key")]
    script = " && ".join(f"chown {owner} /s/{name} && chmod {mode} /s/{name}" for name, owner, mode in todo)
    subprocess.run([engine, "run", "--rm", "-v", f"{SECRETS}:/s", BUSYBOX, "sh", "-c", script],
                   check=True)


def person(spec: str, what: str) -> dict:
    m = re.fullmatch(r"\s*(.+?)\s*<([^<>@\s]+@[^<>@\s]+)>\s*", spec)
    if not m:
        sys.exit(f"--{what} {spec!r}: no name and e-mail address found; give it as \"First Last <e-mail>\", quoted")
    name, email = m.group(1).split(), m.group(2).lower()
    return {"username": re.sub(r"[^a-z0-9._-]", "-", email.split("@")[0]), "email": email, "first_name": name[0],
            "last_name": " ".join(name[1:]) or name[0], "anchor": f"op:{uuid.uuid4()}",
            "password": secrets.token_urlsafe(18)}


def local_ca(names: list[str]) -> tuple[str, str, str]:
    """A local CA (ten years) and a leaf for the front (825 days, the three names and localhost), both P-256."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    pem = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,  # noqa: E731
                                    serialization.NoEncryption()).decode()
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ReliKey core local CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    sans = [x509.DNSName(n) for n in names + ["localhost"]] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    # The key identifiers are what strict verifiers ask for (RFC 5280; Python 3.13 refuses a chain without them).
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    as_pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()  # noqa: E731
    return as_pem(ca), as_pem(leaf), pem(key)


def issued_by(crt_pem: str, ca_pem: str) -> bool:
    """crt_pem is a lone certificate that ca_pem's certificate issued: the local CA's leaf, without its chain."""
    from cryptography import x509
    certs = x509.load_pem_x509_certificates(crt_pem.encode())
    try:
        certs[0].verify_directly_issued_by(x509.load_pem_x509_certificate(ca_pem.encode()))
    except Exception:   # another issuer, a bad signature or key type: not this CA's leaf, leave the file alone
        return False
    return len(certs) == 1


def leaf_pin(pem_text: str) -> str:
    """The SHA-256 of the first certificate's DER: what the agent pins (keyclerk.pin_sha256)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return hashlib.sha256(x509.load_pem_x509_certificate(pem_text.encode()).public_bytes(serialization.Encoding.DER)).hexdigest()


def main() -> int:
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--broker-host", required=True, help="the broker's name: sign-in for people and edges")
    a.add_argument("--desk-host", required=True, help="the desk's name, for people")
    a.add_argument("--edge-host", required=True, help="the edge-facing name: the desk's edge routes and the mirror")
    a.add_argument("--fleet-host", help="optional: the fleet page's own name (decision 0026 point 13), signed in at the "
                                        "broker; fleet_page.py --grant <user> admits")
    a.add_argument("--fleet-officers", metavar="U1,U2,U3", help="with --fleet-host: the first officers' broker "
                                        "usernames, at least three; they register passkeys and sign the anchor")
    a.add_argument("--realm", default="relikey")
    a.add_argument("--root", required=True, help="the root holder, \"First Last <e-mail>\"")
    a.add_argument("--security-officer", "--officer", dest="officer", required=True,
                   help="the security officer who appointed the root holder (root.officer): a core administrator, so "
                        "never an edge's officer")
    a.add_argument("--edge-officer", help="a third person, \"First Last <e-mail>\", to be an edge's officer (seals its "
                                          "ceiling): never the root holder, the security officer or a privileged member")
    a.add_argument("--person", action="append", default=[], metavar='"First Last <e-mail>"',
                   help="an ordinary person to grant memberships to (repeatable): no administrator, no edge officer")
    a.add_argument("--entitlement", action="append", default=[], metavar="ID[:RISK]",
                   help="seed a catalogue entry (risk low|elevated|privileged, default elevated) and a top group "
                        "carrying it; an edge target names one (repeatable)")
    a.add_argument("--keyclerk-src", help=f"a KeyClerk git repository to build v{KEYCLERK_VERSION} from")
    a.add_argument("--keyclerk-ref", help="lab only (with --lab): build KeyClerk from this git ref instead of the pinned "
                                          "tag, tagged localhost/keyclerk:lab-<ref>, to try an unreleased KeyClerk")
    a.add_argument("--cert", help="the organisation's certificate for the three names (PEM): the "
                                       "certificate, then the CA that issued it, which enrolment codes pin")
    a.add_argument("--key", help="its private key (PEM)")
    a.add_argument("--port", type=int, default=443, help="the port people and edges reach the front on")
    a.add_argument("--engine", default="podman")
    a.add_argument("--lab", action="store_true", help="add compose.lab.yaml (host network, the front on 8443)")
    a.add_argument("--yes", action="store_true", help="start the reconciler without asking after its first dry run")
    o = a.parse_args()
    if o.keyclerk_ref and not (o.lab and o.keyclerk_src):
        sys.exit("--keyclerk-ref is for a lab only: it needs --lab and --keyclerk-src")
    if o.keyclerk_ref and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,100}", o.keyclerk_ref):
        sys.exit("--keyclerk-ref: a branch, tag or commit name (letters, digits, . _ / -; not starting with -)")
    if os.environ.get("KEYCLERK_IMAGE") and not o.lab:
        sys.exit("KEYCLERK_IMAGE is set in the environment: unset it (only a lab, through --keyclerk-ref, names another "
                 "KeyClerk image)")
    hosts = [h.lower() for h in (o.broker_host, o.desk_host, o.edge_host)]
    if len(set(hosts)) != 3 or not all(HOST.match(h) for h in hosts):
        sys.exit(f"--broker-host, --desk-host and --edge-host ({', '.join(hosts)}): each needs a DNS name of its "
                 "own (lower-case, with a dot), as the front tells the three sides apart by name; give three "
                 "different ones")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", o.realm) or o.realm == "master":
        sys.exit(f"--realm {o.realm}: lower-case letters, digits and dashes, and not master (the broker's own "
                 "administration realm); leave it out for the default relikey")
    if bool(o.cert) != bool(o.key):
        sys.exit("give both --cert and --key, or neither for a local CA")
    port = 8443 if o.lab else o.port
    suffix = "" if port == 443 else f":{port}"
    SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Every directory compose mounts exists before anything starts: a missing bind-mount source is created by the
    # engine as root, and this installer can then neither write into it nor chmod it (full-stack run 5).
    for d in ("sites", "fleet"):   # the front's optional names (Caddyfile); the fleet's configuration (compose.yaml)
        (SECRETS / d).mkdir(exist_ok=True)
        (SECRETS / d).chmod(0o755)

    # DESK_ORIGIN: what a browser's Origin header carries (host:port off 443); the desk checks it on every POST
    write("core.env", f"BROKER_HOST={hosts[0]}\nDESK_HOST={hosts[1]}\nEDGE_HOST={hosts[2]}\nREALM={o.realm}\n"
                      f"BROKER_URL=https://{hosts[0]}{suffix}\nDESK_URL=https://{hosts[1]}{suffix}\n"
                      f"DESK_ORIGIN={hosts[1]}{suffix}\n", owner=None, keep=False)
    db = secrets.token_urlsafe(32)
    if not (SECRETS / "broker-db.env").exists():
        write("broker-db.env", f"POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD={db}\n", owner=None)
        write("broker.env", f"KC_DB_PASSWORD={db}\n", owner=None, keep=False)
    write("broker-admin.env", f"KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap-admin\n"
                              f"KC_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(24)}\n", owner=None)
    write("keyclerk-writer.secret", secrets.token_urlsafe(32) + "\n")
    write("keyclerk-reader.secret", secrets.token_urlsafe(32) + "\n")
    write("relikey-setup.secret", secrets.token_urlsafe(32) + "\n")   # the realm's setup client (stack attack C1)
    write("keyclerk-mgmt.token", secrets.token_urlsafe(32) + "\n")   # the desk's management listener bearer (>=32 chars, 0018)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    if not (SECRETS / "records.key").exists():   # the records key: the signer's alone; the reconciler gets the public half
        k = Ed25519PrivateKey.generate()
        write("records.key", k.private_bytes_raw().hex() + "\n")
        write("records.pub", k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() + "\n", keep=False)
    if o.cert:
        write("front.crt", Path(o.cert).read_text(encoding="utf-8"), owner=None, keep=False)
        write("front.key", Path(o.key).read_text(encoding="utf-8"), owner=None, keep=False)
    elif not (SECRETS / "front.crt").exists():
        ca, crt, key = local_ca(hosts + ([o.fleet_host.lower()] if o.fleet_host else []))
        write("front-ca.crt", ca, owner=None)
        write("front.crt", crt + ca, owner=None)   # the chain: the front presents its CA, which enrolment codes pin
        write("front.key", key, owner=None)
    elif (SECRETS / "front-ca.crt").exists():   # a local CA from before the chain: add it, same leaf, same key
        crt = (SECRETS / "front.crt").read_text(encoding="utf-8")
        ca = (SECRETS / "front-ca.crt").read_text(encoding="utf-8")
        if issued_by(crt, ca):
            write("front.crt", crt.rstrip("\n") + "\n" + ca, owner=None, keep=False)
    if not (SECRETS / "people.json").exists():   # the first people and the desk's first records (read once)
        root, officer = person(o.root, "root"), person(o.officer, "officer")
        people = [root, officer] + ([person(o.edge_officer, "edgeofficer")] if o.edge_officer else [])             + [person(p, "person") for p in o.person]
        if len({p["email"] for p in people}) != len(people):
            twice = sorted({p["email"] for p in people if [q["email"] for q in people].count(p["email"]) > 1})
            sys.exit(f"{', '.join(twice)} given more than once: the root holder, the security officer, the edge "
                     "officer and each --person are different people, so no one approves their own powers. Give each "
                     "role a person of its own")
        write("people.json", json.dumps(people, indent=1) + "\n")
        when = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        # Persons, the catalogue and the groups' carries are records, never desk actions (KeyClerk 0.24.0): a fresh
        # desk can only enrol an edge if the seed already names an entitlement and an edge officer who is no
        # administrator (found by the full-stack run). Once a top group exists, root holds every power over it.
        ents = []
        for e in o.entitlement:
            eid, _, risk = e.partition(":")
            if risk not in ("", "low", "elevated", "privileged"):
                sys.exit(f"--entitlement {e}: risk is low, elevated or privileged")
            ents.append((eid, risk or "elevated"))
        top = max((r for _, r in ents), key=["low", "elevated", "privileged"].index, default=None)
        seed = [f"realm: {o.realm}", "grants: []", "revocations: []", "root:", f"  officer: \"{officer['anchor']}\"",
                f"  holders: [{{anchor: \"{root['anchor']}\", appointed_by: \"{officer['anchor']}\", from: {when}}}]",
                "persons:"]
        # Power over a privileged group is used from an admin persona, never a daily account (KeyClerk 0011a, enforced
        # since 0.16.1), and a tenant account in a privileged group must state purpose admin: with a privileged top
        # group, every seeded person carries its anchor as an admin persona. A real deployment gives each a separate
        # admin account, the daily one with purpose daily (full-stack run 3; KeyClerk's init does the same).
        admin = top == "privileged"
        if admin and not o.lab:
            sys.exit("a privileged entitlement needs a separate admin account per person in its group (KeyClerk 0011a): "
                     "install.py does not create those yet. Seed it as elevated, or add the admin accounts by hand "
                     "after install; --lab uses the daily account as its own admin persona, which proves nothing")
        if admin:
            print("lab: each person's daily account is also its admin persona; this does not satisfy KeyClerk 0011a "
                  "and is never for production", file=sys.stderr)
        seed += [f"  - {{person: {p['username']}, kind: tenant, anchors: [\"{p['anchor']}\"]"
                 + (f", personas: [{{anchor: \"{p['anchor']}\", purpose: admin}}]" if admin else "") + "}"
                 for p in people]
        if ents:
            seed += ["catalogue:"] + [f"  - {{entitlement: {i}, application: relikey, risk: {r}, owner: \"{root['anchor']}\"}}"
                                       for i, r in ents]
            seed += ["groups:", "  - group_id: relikey-access", "    parent: null", f"    max_risk: {top}", "    carries:"]
            seed += [f"      - {{entitlement: {i}, by: \"{root['anchor']}\"}}" for i, _ in ents]
        write("keyclerk-seed.yaml", "\n".join(seed + [""]))

    compose = [o.engine, "compose", "--env-file", str(SECRETS / "core.env"), "-f", str(CORE / "compose.yaml")]
    if o.lab:
        compose += ["-f", str(CORE / "compose.lab.yaml")]
    if o.keyclerk_src:   # KeyClerk's own Containerfile, from the tag, not a working tree (its README)
        ref, image = f"v{KEYCLERK_VERSION}", f"localhost/keyclerk:{KEYCLERK_VERSION}"
        if o.keyclerk_ref:   # a lab trying an unreleased KeyClerk: its own image name, never the pinned one
            ref, image = o.keyclerk_ref, "localhost/keyclerk:lab-" + "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in o.keyclerk_ref)
            print(f"lab: KeyClerk built from {ref} as {image}, not the pinned v{KEYCLERK_VERSION}", file=sys.stderr)
        if not o.keyclerk_ref:   # the pinned release: a good signature from the pinned key, on the pinned commit
            signers = CORE / "keyclerk.allowed_signers"
            v = subprocess.run(["git", "-C", o.keyclerk_src, "-c", f"gpg.ssh.allowedSignersFile={signers}", "tag", "-v", ref],
                               capture_output=True, text=True)
            if v.returncode != 0 or 'Good "git" signature for keyclerk-releases' not in v.stdout + v.stderr:
                sys.exit(f"KeyClerk {ref}: no good signature from the pinned key ({signers.name}); refusing to build "
                         f"it. Check that {o.keyclerk_src} is a clone of KeyClerk's own repository with its tags "
                         f"fetched (git fetch --tags), then see why with: git tag -v {ref}")
            commit = subprocess.run(["git", "-C", o.keyclerk_src, "rev-list", "-n", "1", ref],
                                    capture_output=True, text=True).stdout.strip()
            if commit != KEYCLERK_COMMIT:
                sys.exit(f"KeyClerk {ref} resolves to {commit or 'nothing'}, not the pinned {KEYCLERK_COMMIT}; "
                         "refusing. A moved tag is never built: fetch the tags again from KeyClerk's own repository "
                         "(git fetch --tags --force), and if it still differs, report it to the ReliKey maintainers")
        archive = subprocess.Popen(["git", "-C", o.keyclerk_src, "archive", "--end-of-options", ref], stdout=subprocess.PIPE)
        # -f names the Containerfile: podman finds it by default, docker only looks for "Dockerfile" (full-stack run)
        subprocess.run([o.engine, "build", "-f", "Containerfile", "-t", image, "-"], stdin=archive.stdout, check=True)
        if archive.wait() != 0:
            sys.exit(f"git archive {ref} failed in {o.keyclerk_src} (its message is above); check that the ref exists "
                     "there, then run this installer again: it keeps every secret it wrote")
        if o.keyclerk_ref:
            with open(SECRETS / "core.env", "a", encoding="utf-8") as f:
                f.write(f"KEYCLERK_IMAGE={image}\n")
    fix_owners(o.engine)
    subprocess.run(compose + ["up", "-d", "broker"], check=True)          # with the front and the database
    subprocess.run(compose + ["run", "--rm", "--no-deps", "setup"], check=True)   # the broker is up: recreating
    # its dependencies would try to replace the front, which every service shares a namespace with
    fleet_dir = SECRETS / "fleet"
    fleet_json = fleet_dir / "fleet.json"
    if not fleet_json.exists():   # the known edges are added by fleet_edge.py as edges are enrolled (decision 0026)
        write("fleet/fleet.json", json.dumps({"listen": "127.0.0.1:8093", "state": "/var/lib/relikey-fleet/fleet.json",
                                        "silence_seconds": 300, "edges": {}}, indent=1) + "\n", owner=None)
        fleet_json.chmod(0o644)   # public keys and settings, no secret: the fleet's uid reads it as "other"
    if (ROOT / "agent" / "dist").exists():
        subprocess.run(compose + ["build", "fleet"], check=True)
        subprocess.run(compose + ["up", "-d", "--force-recreate", "--no-deps", "fleet"], check=True)   # a rebuilt binary runs
    subprocess.run(compose + ["up", "-d", "--no-recreate", "signer", "desk", "mirror"]
                   + (["fleet"] if (ROOT / "agent" / "dist").exists() else []), check=True)   # never replaces
    # what runs: podman refuses to replace the front while the others share its namespace

    # The reconciler writes the broker: its first run is a dry run, shown here, and it starts only once that plan is
    # what the operator expects (a fresh realm and a root-only seed plan nothing).
    dry = ["keyclerk.reconcile", "--config", "/etc/keyclerk/keyclerk.yaml", "--records", "/srv/desk/records.yaml",
           "--signing-key", "/etc/keyclerk/records.pub", "--keycloak", "http://127.0.0.1:8080", "--realm", o.realm,
           "--client", "keyclerk-writer", "--secret-file", "/run/secrets/writer", "--reader-client", "keyclerk-reader",
           "--reader-secret-file", "/run/secrets/reader", "--state", "/var/lib/keyclerk", "--once",
           "--approval-issuer", f"https://{hosts[0]}{suffix}/realms/{o.realm}", "--approval-audience", "keyclerk-desk"]
    for _ in range(20):                          # the desk publishes its first records shortly after it starts
        r = subprocess.run(compose + ["run", "--rm", "--no-deps", "reconcile"] + dry, capture_output=True, text=True)
        if r.returncode == 0:
            break
        time.sleep(3)
    print("the reconciler's first run, a dry run (nothing written):\n" + (r.stdout or r.stderr).strip())
    if r.returncode != 0:
        sys.exit("the reconciler's dry run did not pass (its output is above), so it does not start: nothing was "
                 "written to the broker. Fix what it names, then run this installer again (it keeps every secret it "
                 f"wrote), or start it by hand once a dry run passes: {' '.join(compose)} up -d --no-recreate "
                 "reconcile")
    if not o.yes and input("start the reconciler (it applies from now on)? [y/N] ").strip().lower() != "y":
        print(f"not started; when ready: {' '.join(compose)} up -d --no-recreate reconcile")
    else:
        subprocess.run(compose + ["up", "-d", "--no-recreate", "reconcile"], check=True)

    bundle_key = ""
    probe = ("import json,urllib.request;r=urllib.request.Request('http://127.0.0.1:8091/api/v1/edge-key',"
             f"headers={{'Host':'{hosts[2]}'}});print(json.load(urllib.request.urlopen(r,timeout=5))['key'])")
    for _ in range(40):
        r = subprocess.run(compose + ["exec", "-T", "desk", "python", "-c", probe], capture_output=True, text=True)
        if r.returncode == 0 and re.fullmatch(r"[0-9a-f]{64}", r.stdout.strip()):
            bundle_key = r.stdout.strip()
            break
        time.sleep(3)
    pin = leaf_pin((SECRETS / "front.crt").read_text(encoding="utf-8"))
    ca = SECRETS / "front-ca.crt"
    shown = lambda p: p.relative_to(ROOT) if p.is_relative_to(ROOT) else p  # noqa: E731
    if o.fleet_host and (ROOT / "agent" / "dist").exists():   # the fleet page (0026 point 13)
        subprocess.run([sys.executable, str(CORE / "fleet_page.py"), "--host", o.fleet_host, "--engine", o.engine]
                       + (["--officers", o.fleet_officers] if o.fleet_officers else [])
                       + (["--lab"] if o.lab else []), check=True)
    print(f"core up: broker https://{hosts[0]}{suffix}, desk https://{hosts[1]}{suffix}, edges https://{hosts[2]}{suffix}")
    print(f"the desk's bundle key: {bundle_key or 'not read yet: the desk is still starting; GET /api/v1/edge-key'}")
    print(f"the front's certificate pin: {pin}" + (f"  (or the CA: {shown(ca)})" if ca.exists() else ""))
    print(f"an edge reaches two names: the broker's ({hosts[0]}, Warpgate's OIDC issuer) and the edge-facing one:")
    print("  python deploy/edge/install.py --edge <name> --desk https://" + hosts[2] + suffix +
          f" --desk-pin {pin} --bundle-key {bundle_key or '<bundle key>'} --officer-key <the edge officer's key>")
    print(f"first sign-in: the people seeded, temporary passwords in {shown(SECRETS / 'people.json')};"
          " each sets a password and registers a passkey. Then remove the bootstrap admin (deploy/core/README.md).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

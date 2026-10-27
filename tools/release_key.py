#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""ReliKey's release signing key (decision 0027): create it, keep it in Bitwarden, publish its public half.

The maintainer, in their own terminal (Bitwarden asks for the master password itself):

  uv run --with cryptography,bcrypt python tools/release_key.py create
  python tools/release_key.py status

create refuses when the key file, its .pub or the Bitwarden item already exists. It generates an Ed25519 key in
memory with a random passphrase, stores the private key and the passphrase in a new Bitwarden secure note (sent on
stdin, never in an argument), reads the item back and compares it, and only then writes the encrypted key file
(owner-only), its .pub and the repository's relikey.allowed_signers. Nothing secret is printed. If Bitwarden was
locked, it is locked again at the end.

Sign a release tag with the key afterwards:

  git -c gpg.format=ssh -c user.signingkey=~/.ssh/relikey-releases tag -s vX.Y.Z -m vX.Y.Z
  git -c gpg.ssh.allowedSignersFile=relikey.allowed_signers tag -v vX.Y.Z
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRINCIPAL = "relikey-releases"
_PRINCIPAL_RX = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
# Item names travel to the bw command line; on Windows bw is a .cmd shim, so only characters cmd cannot reinterpret.
_ITEM_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class Refused(Exception):
    """A precondition failed; nothing was changed (or the message says what was)."""


def validate_principal(s: str) -> str:
    if not isinstance(s, str) or not _PRINCIPAL_RX.fullmatch(s):
        raise ValueError("principal: lower-case letters, digits and hyphens, at most 63, not starting with a hyphen")
    return s


def validate_item_name(s: str) -> str:
    if not isinstance(s, str) or not _ITEM_RX.fullmatch(s):
        raise ValueError("item name: letters, digits, dot, underscore, hyphen; at most 64")
    return s


def parse_public_key(line: str) -> bytes:
    """An OpenSSH Ed25519 public key line -> its wire blob. ValueError for anything else."""
    if not isinstance(line, str):
        raise ValueError("public key: not text")
    parts = line.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("public key: not an ssh-ed25519 line")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("public key: base64 does not decode") from None
    name = b"ssh-ed25519"
    want = struct.pack(">I", len(name)) + name + struct.pack(">I", 32)
    if len(blob) != len(want) + 32 or not blob.startswith(want):
        raise ValueError("public key: not an Ed25519 key blob")
    return blob


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def signers_line(principal: str, blob: bytes) -> str:
    validate_principal(principal)
    return f'{principal} namespaces="git" ssh-ed25519 {base64.b64encode(blob).decode()}'


def signers_file(principal: str, blob: bytes, date: str) -> str:
    return (
        "# The key that signs ReliKey's release tags (decision 0027); its private half is held by the maintainers.\n"
        f"# Fingerprint {fingerprint(blob)}, created {date}. Verify a tag:\n"
        "#   git -c gpg.ssh.allowedSignersFile=relikey.allowed_signers tag -v vX.Y.Z\n"
        f"{signers_line(principal, blob)}\n"
    )


def find_items(listing: str, name: str) -> list[str]:
    """`bw list items --search NAME` output -> ids of the items named exactly NAME. ValueError if not a listing."""
    try:
        items = json.loads(listing)
    except (json.JSONDecodeError, TypeError, RecursionError):
        raise ValueError("bw listing: not JSON") from None
    if not isinstance(items, list):
        raise ValueError("bw listing: not a list")
    ids = []
    for it in items:
        if isinstance(it, dict) and it.get("name") == name:
            if not isinstance(it.get("id"), str):
                raise ValueError("bw listing: an item without an id")
            ids.append(it["id"])
    return ids


def item_json(name: str, private_pem: str, passphrase: str, blob: bytes) -> dict:
    """A Bitwarden secure note holding the key; the passphrase in a hidden field."""
    validate_item_name(name)
    return {
        "type": 2, "secureNote": {"type": 0}, "name": name, "favorite": False, "reprompt": 1,
        "notes": private_pem,
        "fields": [
            {"name": "passphrase", "value": passphrase, "type": 1},
            {"name": "public_key", "value": f"ssh-ed25519 {base64.b64encode(blob).decode()}", "type": 0},
            {"name": "fingerprint", "value": fingerprint(blob), "type": 0},
        ],
    }


def stored_matches(stored: str, private_pem: str, passphrase: str) -> bool:
    """Does the item Bitwarden returned hold exactly this key and passphrase?"""
    try:
        it = json.loads(stored)
    except (json.JSONDecodeError, TypeError, RecursionError):
        return False
    if not isinstance(it, dict) or it.get("notes") != private_pem:
        return False
    fields = it.get("fields")
    if not isinstance(fields, list):
        return False
    vals = [f.get("value") for f in fields if isinstance(f, dict) and f.get("name") == "passphrase"]
    return vals == [passphrase]


class Bitwarden:
    """The bw CLI. RELIKEY_BW (a JSON argv list) replaces the command, for tests."""

    def __init__(self) -> None:
        override = os.environ.get("RELIKEY_BW")
        if override:
            self.cmd = json.loads(override)
        else:
            exe = shutil.which("bw")
            if not exe:
                raise Refused("bw (the Bitwarden CLI) is not on PATH")
            self.cmd = [exe]
        self.env = dict(os.environ)
        self.unlocked_here = False

    def run(self, *args: str, stdin: str | None = None) -> str:
        proc = subprocess.run([*self.cmd, *args], input=stdin, capture_output=True, text=True, env=self.env)
        if proc.returncode != 0:
            # bw's own message, never our input: stdin may hold the key.
            tail = proc.stderr.strip().splitlines()
            raise Refused(f"bw {args[0]} failed: {tail[-1] if tail else f'exit {proc.returncode}'}")
        return proc.stdout

    def unlock(self) -> None:
        if self.env.get("BW_SESSION"):
            return
        # bw asks for the master password on the terminal; only the session key comes back on stdout.
        proc = subprocess.run([*self.cmd, "unlock", "--raw"], stdout=subprocess.PIPE, text=True, env=self.env)
        session = (proc.stdout or "").strip()
        if proc.returncode != 0 or not session:
            raise Refused("bw unlock failed; nothing was changed")
        self.env["BW_SESSION"] = session
        self.unlocked_here = True

    def lock(self) -> None:
        if self.unlocked_here:
            subprocess.run([*self.cmd, "lock"], capture_output=True, env=self.env)


def generate(principal: str) -> tuple[str, str, bytes]:
    """-> (encrypted OpenSSH private key text, passphrase, public blob)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    passphrase = secrets.token_urlsafe(32)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                            serialization.BestAvailableEncryption(passphrase.encode())).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return pem, passphrase, parse_public_key(pub)


def write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
        f.write(text)
    if os.name == "nt" and os.environ.get("USERNAME"):
        # OpenSSH on Windows refuses a key others can read: owner only, no inherited entries.
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{os.environ['USERNAME']}:F"],
                       capture_output=True, check=True)


def create(key: Path, item: str, principal: str, signers: Path, today: str) -> str:
    validate_principal(principal)
    validate_item_name(item)
    pub = key.with_name(key.name + ".pub")
    for p in (key, pub, signers):
        if p.exists():
            raise Refused(f"{p} exists; nothing was changed (rotation: retire the old key first)")
    if not key.parent.is_dir():
        raise Refused(f"{key.parent} does not exist; nothing was changed")

    bw = Bitwarden()
    bw.unlock()
    try:
        bw.run("sync")
        if find_items(bw.run("list", "items", "--search", item), item):
            raise Refused(f"a Bitwarden item named {item} exists; nothing was changed")
        pem, passphrase, blob = generate(principal)
        payload = base64.b64encode(json.dumps(item_json(item, pem, passphrase, blob)).encode()).decode()
        created = json.loads(bw.run("create", "item", stdin=payload))
        item_id = created.get("id") if isinstance(created, dict) else None
        if not isinstance(item_id, str) or not stored_matches(bw.run("get", "item", item_id), pem, passphrase):
            raise Refused(f"the Bitwarden item {item} does not read back as written; no key file was written. "
                          "Delete that item in Bitwarden and run create again")
        # Bitwarden holds the key; only now does it touch the disk.
        write_private(key, pem)
        pub.write_text(f"ssh-ed25519 {base64.b64encode(blob).decode()} {principal}\n", encoding="ascii")
        signers.write_text(signers_file(principal, blob, today), encoding="ascii", newline="\n")
        return fingerprint(blob)
    finally:
        bw.lock()


def status(key: Path, signers: Path, principal: str) -> int:
    pub = key.with_name(key.name + ".pub")
    bad = 0
    try:
        blob = parse_public_key(pub.read_text(encoding="ascii"))
        print(f"OK    {pub}: {fingerprint(blob)}")
    except (OSError, ValueError) as e:
        print(f"MISS  {pub}: {e}")
        return 1
    print(("OK    " if key.exists() else "MISS  ") + str(key))
    bad |= not key.exists()
    want = signers_line(principal, blob)
    try:
        lines = [ln.strip() for ln in signers.read_text(encoding="ascii").splitlines()]
        ok = want in lines
    except OSError:
        ok = False
    print(("OK    " if ok else "DRIFT ") + f"{signers} names this key for {principal}")
    return int(bad or not ok)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["create", "status"])
    ap.add_argument("--key", type=Path, default=Path.home() / ".ssh" / PRINCIPAL)
    ap.add_argument("--item", default=PRINCIPAL, help="Bitwarden item name")
    ap.add_argument("--principal", default=PRINCIPAL)
    ap.add_argument("--signers", type=Path, default=REPO / "relikey.allowed_signers")
    a = ap.parse_args(argv)
    if a.command == "status":
        return status(a.key, a.signers, a.principal)
    try:
        fp = create(a.key, a.item, a.principal, a.signers, datetime.date.today().isoformat())
    except (Refused, ValueError) as e:
        print(f"release_key: {e}", file=sys.stderr)
        return 2
    print(f"Created {a.key} ({fp}); private key and passphrase in Bitwarden item {a.item}; wrote {a.signers}.")
    print("Commit relikey.allowed_signers. Sign tags as in this script's header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

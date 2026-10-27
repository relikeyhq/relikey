# SPDX-License-Identifier: EUPL-1.2
"""Apply an edge's targets to its Warpgate: for each one, the role a lease names, the target, the role bound to it and
the target's pinned host key. Idempotent: run it again after any change to the file (the installation's part of
"the installation creates roles and binds them to targets"; the agent only assigns roles from signed leases).

    python deploy/edge/targets.py deploy/edge/targets.yaml          # after: compose up -d

targets.yaml:
    targets:
      - name: plc-ssh                  # the target an enrolment names (enrol_edge targets[].target)
        role: plc-operators            # the role a lease for it names (enrol_edge targets[].role)
        ssh: {host: 10.0.0.5, port: 22, username: plcuser}
        host_key: "ssh-ed25519 AAAA..."   # the target's own host key, verified out of band: required

Warpgate authenticates to an SSH target with its own client key; the keys it prints at the end go into the legacy
account's authorized_keys. A target without host_key is refused: Warpgate would trust whatever key answers first, and
it refuses a non-interactive first contact anyway (full-stack run, 2026-10-24).

It also writes deploy/secrets/governed-roles.json: the roles of this file, which only leases grant, as a SCIM list of
groups (RFC 7643). The agent reads it every tick and reports an account it does not manage that holds one of them,
never changing it (full-stack run 2, finding 8). The file is the edge's own source of what is governed and stays one;
with a clerk's signed catalogue in the bundle (KeyClerk 0.25.0, its decision 0025) the agent governs the union.
"""
import argparse
import hashlib
import http.client
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
GOVERNED = ROOT / "deploy" / "secrets" / "governed-roles.json"   # compose.yaml mounts it into the agent
API = "https://127.0.0.1:8899/@warpgate/admin/api"     # Warpgate on this edge's loopback only (the front owns 8888)


def warpgate_pin() -> str:
    """The sha256 of Warpgate's certificate, as install.py recorded it (warpgate.pin, or agent.json if readable)."""
    secrets_dir = ROOT / "deploy" / "secrets"
    try:
        pin = (secrets_dir / "warpgate.pin").read_text(encoding="utf-8").strip()
    except OSError:
        try:
            pin = json.loads((secrets_dir / "agent.json").read_text(encoding="utf-8"))["bastion"]["pin_sha256"]
        except (OSError, KeyError, ValueError):
            pin = ""
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        sys.exit("no pin for Warpgate's certificate (deploy/secrets/warpgate.pin): run deploy/edge/install.py again, or "
                 "write the agent's bastion.pin_sha256 there; nothing was sent")
    return pin


class PinnedHTTPS(urllib.request.HTTPSHandler):
    """Sends the admin token only to the Warpgate whose certificate install.py pinned: a local user who binds
    127.0.0.1:8899 while the edge is down gets nothing (stack attack 2026-10-25, E8)."""

    def __init__(self, pin: str):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # self-signed: the pin is the check
        super().__init__(context=ctx)
        self.pin = pin

    def https_open(self, req):
        pin = self.pin

        class Conn(http.client.HTTPSConnection):
            def connect(self):
                super().connect()
                der = self.sock.getpeercert(binary_form=True) or b""
                if hashlib.sha256(der).hexdigest() != pin:
                    self.sock.close()
                    raise ssl.SSLError("127.0.0.1:8899 answered with a certificate that is not Warpgate's pinned one")

        return self.do_open(Conn, req, context=self._context)


def call(token: str, method: str, path: str, body=None):
    req = urllib.request.Request(API + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"X-Warpgate-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.build_opener(PinnedHTTPS(warpgate_pin())).open(req, timeout=15) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        sys.exit(f"Warpgate {method} {path}: {e.code} {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        sys.exit(f"Warpgate is not answering on 127.0.0.1:8899 ({e.reason}): start the edge first "
                 "(compose up -d) and check `docker logs` of its warpgate container; nothing was changed")


def write_governed(roles: list[str]) -> None:
    """The governed roles as a SCIM ListResponse of Groups. Written in place, not replaced: compose bind-mounts this
    one file, and a renamed file would leave the agent reading the old one. A torn read is never valid JSON, so the
    agent notes it for a tick and never reads it as nothing governed."""
    doc = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": len(roles),
           "Resources": [{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": r} for r in roles]}
    with open(GOVERNED, "r+" if GOVERNED.exists() else "w", encoding="utf-8") as f:
        f.seek(0)
        f.write(json.dumps(doc, indent=1) + "\n")
        f.truncate()
    print(f"governed roles: {', '.join(roles) or 'none'} ({GOVERNED.relative_to(ROOT).as_posix()}, read by the agent)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets_file", help="the edge's targets.yaml (copy targets.example.yaml)")
    args = ap.parse_args()
    spec = yaml.safe_load(Path(args.targets_file).read_text(encoding="utf-8")) or {}
    try:
        token = (ROOT / "deploy" / "secrets" / "warpgate.token").read_text(encoding="utf-8").strip()
    except PermissionError:     # the agent's copy (install.py fix_owners); warpgate.env holds the same token
        env = (ROOT / "deploy" / "secrets" / "warpgate.env").read_text(encoding="utf-8")
        token = next(ln.split("=", 1)[1].strip() for ln in env.splitlines() if ln.startswith("WARPGATE_ADMIN_TOKEN="))
    problems = []
    for t in spec.get("targets", []):
        for k in ("name", "role", "ssh", "host_key"):
            if not t.get(k):
                problems.append(f"target {t.get('name', '?')}: {k} is missing" +
                                (" (the target's host key, verified out of band; no trust on first use)" if k == "host_key" else ""))
    if problems:
        sys.exit("refused, nothing changed:\n  " + "\n  ".join(problems))

    roles = {r["name"]: r["id"] for r in call(token, "GET", "/roles")}
    targets = {t["name"]: t for t in call(token, "GET", "/targets")}
    known = {(k["host"], k["port"], k["key_type"], k["key_base64"]) for k in call(token, "GET", "/ssh/known-hosts")}
    for t in spec["targets"]:
        s = t["ssh"]
        host, port, user = s["host"], int(s.get("port", 22)), s["username"]
        if t["role"] not in roles:
            roles[t["role"]] = call(token, "POST", "/roles", {"name": t["role"], "description": f"lease role for {t['name']}"})["id"]
            print(f"role {t['role']}: created")
        body = {"name": t["name"], "ticket_requests_disabled": True, "ticket_require_approval": False,
                "require_approval": False,
                "options": {"kind": "Ssh", "host": host, "port": port, "username": user, "allow_insecure_algos": False,
                            "auth": {"kind": "PublicKey"}}}
        if t["name"] in targets:
            tid = targets[t["name"]]["id"]
            call(token, "PUT", f"/targets/{tid}", body)
            print(f"target {t['name']}: kept (updated to the file)")
        else:
            tid = call(token, "POST", "/targets", body)["id"]
            print(f"target {t['name']}: created ({user}@{host}:{port})")
        bound = {r["name"] for r in (call(token, "GET", f"/targets/{tid}/roles") or [])}
        if t["role"] not in bound:
            call(token, "POST", f"/targets/{tid}/roles/{roles[t['role']]}")
            print(f"target {t['name']}: role {t['role']} bound")
        key_type, key_b64 = t["host_key"].split()[:2]
        if (host, port, key_type, key_b64) not in known:
            call(token, "POST", "/ssh/known-hosts", {"host": host, "port": port, "key_type": key_type, "key_base64": key_b64})
            print(f"target {t['name']}: host key pinned ({key_type})")
    write_governed(sorted({t["role"] for t in spec["targets"]}))
    print("\nWarpgate's client keys - put them in each SSH target account's authorized_keys:")
    # restrict: the lease reaches the target's shell, not what the target can reach (no -L/-D/-R, no agent or X11
    # forwarding: stack attack 2026-10-25, E9); pty keeps an interactive shell.
    for k in call(token, "GET", "/ssh/own-keys"):
        print("  restrict,pty " + k["public_key"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

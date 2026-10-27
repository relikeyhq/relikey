# SPDX-License-Identifier: EUPL-1.2
"""Register one edge's Warpgate at the core's broker (decision 0010): a confidential client warpgate-<edge> with PKCE
and its one return URL, in the realm install.py set up.

    python deploy/core/add_edge.py --edge plant-a --warpgate-url https://plant-a.example:8888 [--engine podman] [--lab]

The client secret is made once into deploy/secrets/warpgate-<edge>.secret (0600, git-ignored) and handed to realm.py
on stdin; it is never printed. Carry that file to the edge, out of band, for its install.py (--sso-secret-file).
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


def env(name: str) -> str:
    for line in (SECRETS / "core.env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    sys.exit(f"{name} missing from deploy/secrets/core.env: run deploy/core/install.py first")


def main() -> int:
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--edge", required=True)
    a.add_argument("--warpgate-url", required=True, help="Warpgate's external URL, https://host[:port]")
    a.add_argument("--engine", default="podman")
    a.add_argument("--lab", action="store_true")
    o = a.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", o.edge):
        sys.exit("--edge: lower-case letters, digits and dashes")
    if not (SECRETS / "core.env").exists():
        sys.exit("no deploy/secrets/core.env: run deploy/core/install.py first")
    f = SECRETS / f"warpgate-{o.edge}.secret"
    if not f.exists():
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(secrets.token_urlsafe(32) + "\n")
    compose = [o.engine, "compose", "--env-file", str(SECRETS / "core.env"), "-f", str(CORE / "compose.yaml")]
    if o.lab:
        compose += ["-f", str(CORE / "compose.lab.yaml")]
    subprocess.run(compose + ["run", "--rm", "--no-deps", "-T", "setup", "edge", o.edge, o.warpgate_url],
                   input=f.read_text(encoding="utf-8"), text=True, check=True)
    issuer = f"{env('BROKER_URL')}/realms/{env('REALM')}"
    print(f"edge {o.edge}: carry {f.relative_to(ROOT)} to the edge, then on the edge:\n"
          f"  python deploy/edge/install.py --edge {o.edge} ... --warpgate-url {o.warpgate_url} --sso-issuer {issuer}"
          f" --sso-secret-file warpgate-{o.edge}.secret"
          + (" --sso-ca front-ca.crt" if (SECRETS / "front-ca.crt").exists() else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Run the agent's Warpgate adapter against a real Warpgate, one version at a time.

    python tools/warpgate_live.py 0.30.4 [0.30.2 ...] [--engine podman|docker]

For each version: pulls the official image, sets it up as deploy/edge does (unattended setup, then
`run --enable-admin-token` with a fresh WARPGATE_ADMIN_TOKEN), publishes it on 127.0.0.1 only, and runs
TestLiveWarpgate (agent/internal/warpgate/live_test.go) against it. The token and the admin password are random and
kept nowhere; the container and its volume are removed afterwards. Use it before moving the edge to a new Warpgate.
"""
import argparse
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import ssl
from pathlib import Path

AGENT = Path(__file__).resolve().parent.parent / "agent"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_up(url: str, seconds: int = 60) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # the throwaway Warpgate's own certificate
    for _ in range(seconds):
        try:
            urllib.request.urlopen(url, context=ctx, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(1)
    return False


def run_one(engine: str, version: str) -> bool:
    name = f"relikey-live-warpgate-{version.replace('.', '-')}"
    image = f"ghcr.io/warp-tech/warpgate:{version}"
    token, password = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    port = free_port()
    sh = lambda *a, **k: subprocess.run([engine, *a], check=True, capture_output=True, text=True, **k)  # noqa: E731
    try:
        sh("pull", "-q", image)
        sh("volume", "create", name)
        # The password reaches the container through its environment, never argv (as deploy/edge/install.py does).
        sh("run", "--rm", "-e", "WARPGATE_ADMIN_PASSWORD", "-v", f"{name}:/data", image, "--config",
           "/data/warpgate.yaml", "unattended-setup", "--data-path", "/data", "--http-port", "8888", "--ssh-port", "2222",
           env={**os.environ, "WARPGATE_ADMIN_PASSWORD": password})
        sh("run", "-d", "--name", name, "-e", "WARPGATE_ADMIN_TOKEN", "-v", f"{name}:/data", "-p", f"127.0.0.1:{port}:8888",
           image, "--config", "/data/warpgate.yaml", "run", "--enable-admin-token",
           env={**os.environ, "WARPGATE_ADMIN_TOKEN": token})
        base = f"https://127.0.0.1:{port}/@warpgate"
        if not wait_up(base + "/api/info"):
            print(f"{version}: Warpgate did not answer within a minute; see `{engine} logs {name}`")
            return False
        r = subprocess.run(["go", "test", "-count=1", "-run", "TestLiveWarpgate", "-v", "./internal/warpgate"], cwd=AGENT,
                           capture_output=True, text=True,
                           env={**os.environ, "RELIKEY_LIVE_WARPGATE_URL": base + "/admin/api",
                                "RELIKEY_LIVE_WARPGATE_TOKEN": token})
        ok = r.returncode == 0 and "--- PASS: TestLiveWarpgate" in r.stdout
        print(f"{version}: {'pass' if ok else 'FAIL'}")
        if not ok:
            print(r.stdout[-3000:], r.stderr[-2000:], sep="\n")
        return ok
    except subprocess.CalledProcessError as e:
        print(f"{version}: {' '.join(e.cmd[:3])} failed: {e.stderr.strip()[-500:]}")
        return False
    finally:
        subprocess.run([engine, "rm", "-f", name], capture_output=True)
        subprocess.run([engine, "volume", "rm", "-f", name], capture_output=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("versions", nargs="+", help="Warpgate versions, e.g. 0.30.4")
    ap.add_argument("--engine", default="podman", choices=["podman", "docker"])
    o = ap.parse_args()
    results = [run_one(o.engine, v) for v in o.versions]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

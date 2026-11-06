#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Run the agent's Warpgate adapter against a real Warpgate, one version at a time.

    python tools/warpgate_live.py 0.30.4 [0.30.2 ...] [--engine podman|docker] [--rdp]

For each version: pulls the official image, sets it up as deploy/edge does (unattended setup, then
`run --enable-admin-token` with a fresh WARPGATE_ADMIN_TOKEN), publishes it on 127.0.0.1 only, and runs
TestLiveWarpgate (agent/internal/warpgate/live_test.go) against it. The token and the admin password are random and
kept nowhere; the container and its volume are removed afterwards. Use it before moving the edge to a new Warpgate.

With --rdp it also runs TestLiveWarpgateRDP (agent/internal/warpgate/live_rdp_test.go): it builds an xrdp target and a
FreeRDP client from tools/rdp-live/ (Debian, pinned by digest), puts Warpgate (with its RDP listener and recording on)
and the target on a network of their own, and holds a real RDP session through Warpgate that the adapter then ends.
"""
import argparse
import json
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


RDP_LIVE = Path(__file__).resolve().parent / "rdp-live"


def run_one(engine: str, version: str, rdp: bool = False) -> bool:
    name = f"relikey-live-warpgate-{version.replace('.', '-')}"
    net, target = name + "-net", name + "-rdp-target"
    target_pw = secrets.token_urlsafe(24)
    image = f"ghcr.io/warp-tech/warpgate:{version}"
    token, password = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    port = free_port()
    sh = lambda *a, **k: subprocess.run([engine, *a], check=True, capture_output=True, text=True, **k)  # noqa: E731
    try:
        sh("pull", "-q", image)
        sh("volume", "create", name)
        rdp_setup, net_args = [], []
        if rdp:
            for part in ("target", "client"):
                sh("build", "-q", "-t", f"localhost/relikey-rdp-{part}:live", str(RDP_LIVE / part))
            sh("network", "create", net)
            sh("run", "-d", "--name", target, "--network", net, "-e", "RK_PASSWORD", "localhost/relikey-rdp-target:live",
               env={**os.environ, "RK_PASSWORD": target_pw})
            rdp_setup, net_args = ["--rdp-port", "3389", "--record-sessions"], ["--network", net]
        # The password reaches the container through its environment, never argv (as deploy/edge/install.py does).
        sh("run", "--rm", "-e", "WARPGATE_ADMIN_PASSWORD", "-v", f"{name}:/data", image, "--config",
           "/data/warpgate.yaml", "unattended-setup", "--data-path", "/data", "--http-port", "8888", "--ssh-port", "2222",
           *rdp_setup,
           env={**os.environ, "WARPGATE_ADMIN_PASSWORD": password})
        sh("run", "-d", "--name", name, *net_args, "-e", "WARPGATE_ADMIN_TOKEN", "-v", f"{name}:/data", "-p", f"127.0.0.1:{port}:8888",
           image, "--config", "/data/warpgate.yaml", "run", "--enable-admin-token",
           env={**os.environ, "WARPGATE_ADMIN_TOKEN": token})
        base = f"https://127.0.0.1:{port}/@warpgate"
        if not wait_up(base + "/api/info"):
            print(f"{version}: Warpgate did not answer within a minute; see `{engine} logs {name}`")
            return False
        env = {**os.environ, "RELIKEY_LIVE_WARPGATE_URL": base + "/admin/api", "RELIKEY_LIVE_WARPGATE_TOKEN": token}
        if rdp:
            env.update({"RELIKEY_LIVE_RDP_TARGET": target, "RELIKEY_LIVE_RDP_TARGET_PASSWORD": target_pw,
                        "RELIKEY_LIVE_RDP_CLIENT": json.dumps([sys.executable, str(RDP_LIVE / "client.py")]),
                        "RELIKEY_LIVE_RDP_ENGINE": engine, "RELIKEY_LIVE_RDP_NET": net, "RELIKEY_LIVE_RDP_WARPGATE": name})
        r = subprocess.run(["go", "test", "-count=1", "-run", "TestLiveWarpgate", "-v", "./internal/warpgate"], cwd=AGENT,
                           capture_output=True, text=True, env=env)
        ok = r.returncode == 0 and "--- PASS: TestLiveWarpgate " in r.stdout + " " and (
            not rdp or "--- PASS: TestLiveWarpgateRDP" in r.stdout)
        print(f"{version}: {'pass' if ok else 'FAIL'}")
        if not ok:
            print(r.stdout[-3000:], r.stderr[-2000:], sep="\n")
        return ok
    except subprocess.CalledProcessError as e:
        print(f"{version}: {' '.join(e.cmd[:3])} failed: {e.stderr.strip()[-500:]}")
        return False
    finally:
        subprocess.run([engine, "rm", "-f", name, target], capture_output=True)
        subprocess.run([engine, "volume", "rm", "-f", name], capture_output=True)
        subprocess.run([engine, "network", "rm", "-f", net], capture_output=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("versions", nargs="+", help="Warpgate versions, e.g. 0.30.4")
    ap.add_argument("--engine", default="podman", choices=["podman", "docker"])
    ap.add_argument("--rdp", action="store_true", help="also hold a real RDP session through Warpgate (TestLiveWarpgateRDP)")
    o = ap.parse_args()
    results = [run_one(o.engine, v, o.rdp) for v in o.versions]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

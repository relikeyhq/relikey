#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""The RDP client TestLiveWarpgateRDP drives (RELIKEY_LIVE_RDP_CLIENT): FreeRDP under a virtual display, in a
container on the test's network, holding one session through Warpgate.

    client.py              start a client for RDP_USER and RDP_PASSWORD (from the environment); prints its container
    client.py running ID   prints true or false
    client.py stop ID      removes it

RELIKEY_LIVE_RDP_ENGINE, RELIKEY_LIVE_RDP_NET and RELIKEY_LIVE_RDP_WARPGATE (the Warpgate container's name) come from
tools/warpgate_live.py. The password reaches the container through its environment, never argv.
"""
import os
import secrets
import subprocess
import sys

ENGINE = os.environ.get("RELIKEY_LIVE_RDP_ENGINE", "podman")


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "running":
        r = subprocess.run([ENGINE, "inspect", "-f", "{{.State.Running}}", sys.argv[2]], capture_output=True, text=True)
        print("true" if r.returncode == 0 and r.stdout.strip() == "true" else "false")
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "stop":
        subprocess.run([ENGINE, "rm", "-f", sys.argv[2]], capture_output=True)
        return 0
    name = "relikey-live-rdp-client-" + secrets.token_hex(4)
    env = {**os.environ, "RDP_HOST": os.environ["RELIKEY_LIVE_RDP_WARPGATE"]}
    subprocess.run([ENGINE, "run", "-d", "--name", name, "--network", os.environ["RELIKEY_LIVE_RDP_NET"], "-e", "RDP_HOST",
                    "-e", "RDP_USER", "-e", "RDP_PASSWORD", "localhost/relikey-rdp-client:live"], check=True,
                   capture_output=True, env=env)
    print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())

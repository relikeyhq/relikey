# SPDX-License-Identifier: EUPL-1.2
"""Make an edge known to the fleet service (decision 0026): its enrolment public key goes into deploy/secrets/fleet.json
and the fleet service restarts to read it. Run it on the core once the edge is enrolled (the same key the desk enrolled).

    python deploy/core/fleet_edge.py --edge plant-a --key <the edge's enrolment public key, 64 hex> [--engine docker] [--lab]
    python deploy/core/fleet_edge.py --edge plant-a --remove [--engine docker] [--lab]

Without a clerk this file is the fleet's list of known edges; with a clerk, its enrolled edges will feed it (later).
"""
import argparse
import fcntl
import os
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRETS = ROOT / "deploy" / "secrets"
CORE = ROOT / "deploy" / "core"


def save(change) -> int:
    """Change fleet.json under a lock (two runs at once never lose a change) and replace it atomically: written beside
    it, synced, renamed over it. compose mounts the fleet/ directory, so the service sees the new file after its
    restart; a crash leaves the old file or the new one, never half of one. Returns the number of known edges."""
    path = SECRETS / "fleet" / "fleet.json"
    with open(path.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cfg = json.loads(path.read_text(encoding="utf-8"))
        change(cfg)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(cfg, indent=1) + "\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o644)
        tmp.replace(path)
    return len(cfg["edges"])


def main() -> int:
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--edge", required=True)
    a.add_argument("--key", help="the edge's enrolment public key, 64 lower-case hex")
    a.add_argument("--remove", action="store_true", help="forget the edge")
    a.add_argument("--engine", default="podman")
    a.add_argument("--lab", action="store_true", help="the core was installed with --lab")
    o = a.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", o.edge):
        sys.exit("--edge: lower-case letters, digits and hyphens")
    if not o.remove and not (o.key and re.fullmatch(r"[0-9a-f]{64}", o.key)):
        sys.exit("--key: the edge's enrolment public key, 64 lower-case hex (or --remove)")
    n = save(lambda cfg: cfg["edges"].pop(o.edge, None) if o.remove else cfg["edges"].__setitem__(o.edge, o.key))
    compose = [o.engine, "compose", "--env-file", str(SECRETS / "core.env"), "-f", str(CORE / "compose.yaml")]
    if o.lab:
        compose += ["-f", str(CORE / "compose.lab.yaml")]
    subprocess.run(compose + ["restart", "fleet"], check=True)
    print(f"fleet: {o.edge} {'removed' if o.remove else 'known'}; {n} edge(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

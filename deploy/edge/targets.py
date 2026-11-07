# SPDX-License-Identifier: EUPL-1.2
"""Apply an edge's targets to its Warpgate: for each one, the role a lease names, the target, the role bound to it and
the target's pinned host key. Idempotent: run it again after any change to the file (the installation's part of
"the installation creates roles and binds them to targets"; the agent's loop only assigns roles from signed leases).

    python deploy/edge/targets.py deploy/edge/targets.yaml          # after: compose up -d

targets.yaml:
    targets:
      - name: plc-ssh                  # the target an enrolment names (enrol_edge targets[].target)
        role: plc-operators            # the role a lease for it names (enrol_edge targets[].role)
        ssh: {host: 10.0.0.5, port: 22, username: plcuser}
        host_key: "ssh-ed25519 AAAA..."   # the target's own host key, verified out of band: required

Warpgate's admin API listens on the pod's loopback only (decision 0008), which the host cannot reach. So this checks the
file here and hands it to the agent's `targets` command inside the pod (`compose exec agent`), which applies it with the
agent's own pinned certificate and token (walk 2026-11-06, F14). The pod must be running.

Warpgate authenticates to an SSH target with its own client key; the keys it prints at the end go into the legacy
account's authorized_keys. A target without host_key is refused: Warpgate would trust whatever key answers first, and
it refuses a non-interactive first contact anyway (full-stack run, 2026-10-24).

It also writes deploy/secrets/governed-roles.json: the roles of this file, which only leases grant, as a SCIM list of
groups (RFC 7643). The agent reads it every tick and reports an account it does not manage that holds one of them,
never changing it (full-stack run 2, finding 8). The file is the edge's own source of what is governed and stays one;
with a clerk's signed catalogue in the bundle (KeyClerk 0.25.0, its decision 0025) the agent governs the union.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "edge" / "compose.yaml"
GOVERNED = ROOT / "deploy" / "secrets" / "governed-roles.json"   # compose.yaml mounts it into the agent


def check(spec) -> list[dict]:
    """The targets, or exit with every problem at once; nothing is sent for a file with one."""
    targets = (spec or {}).get("targets") if isinstance(spec, dict) else None
    if not isinstance(targets, list) or not targets:
        sys.exit("refused, nothing changed: the file has no `targets:` list (deploy/edge/targets.example.yaml shows one)")
    problems = []
    for t in targets:
        if not isinstance(t, dict):
            problems.append(f"{t!r}: each target is a mapping with name, role, ssh and host_key")
            continue
        for k in ("name", "role", "ssh", "host_key"):
            if not t.get(k):
                problems.append(f"target {t.get('name', '?')}: {k} is missing" +
                                (" (the target's host key, verified out of band; no trust on first use)" if k == "host_key" else ""))
        ssh = t.get("ssh") or {}
        for k in ("host", "username"):
            if isinstance(ssh, dict) and t.get("ssh") and not ssh.get(k):
                problems.append(f"target {t.get('name', '?')}: ssh.{k} is missing")
    if problems:
        sys.exit("refused, nothing changed:\n  " + "\n  ".join(problems))
    return [{"name": t["name"], "role": t["role"], "host_key": t["host_key"],
             "ssh": {"host": t["ssh"]["host"], "port": int(t["ssh"].get("port", 22)), "username": t["ssh"]["username"]}}
            for t in targets]


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
    ap.add_argument("--engine", default="podman", help="podman (default) or docker, as for the edge's installer")
    args = ap.parse_args()
    targets = check(yaml.safe_load(Path(args.targets_file).read_text(encoding="utf-8")))
    cmd = [args.engine, "compose", "-f", str(COMPOSE), "exec", "-T", "agent", "/relikey-agent", "targets", "-in", "-"]
    try:
        r = subprocess.run(cmd, input=json.dumps({"targets": targets}), text=True)
    except FileNotFoundError:
        sys.exit(f"{args.engine} is not installed here; give --engine docker or podman, as for the edge's installer")
    if r.returncode != 0:
        sys.exit(f"the agent did not apply the targets (exit {r.returncode}): read its message above. If the agent "
                 f"is not running, start the edge first ({args.engine} compose -f deploy/edge/compose.yaml up -d) "
                 "and check its log; governed-roles.json was not changed")
    write_governed(sorted({t["role"] for t in targets}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

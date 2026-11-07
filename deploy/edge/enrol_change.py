# SPDX-License-Identifier: EUPL-1.2
"""Write the enrol_edge change the desk's Edges page asks for, from the statement the officer and the edge signed and
the edge's targets file, so every field is what the two signed (rc.4 walk W2, #177: a change written by hand left out
the unlock key on the rc.3 walk, and the desk refused it as "nodes differ").

    python deploy/edge/enrol_change.py --statement st2.json --targets deploy/edge/targets.yaml \\
        --name "Plant A" [--entitlement plc-ssh=plc-ssh ...] [--profile basic] > enrol.json

Root pastes enrol.json into "Enrol or rotate an edge" on the desk's Edges page and presses Review. The statement is the
one `relikey-agent cosign` wrote (st2.json): the officer's and the edge's signatures over one statement. Each target's
entitlement is the catalogue entry that grants it (the core's --entitlement); without --entitlement for a target, its
name is taken, as the install guide's example does. Nothing is sent anywhere: the desk checks the signatures itself.
"""
import argparse
import base64
import json
import re
import sys
from pathlib import Path

import yaml

ANCHOR = re.compile(r"[a-z][a-z0-9-]*:\S+")   # a person's anchor at the desk: provider-prefixed (op:, idp:, ...)


def says_of(statement: dict) -> dict:
    """What the statement says: its signed bytes, decoded."""
    raw = statement.get("bytes")
    if not isinstance(raw, str):
        sys.exit("refused: not a signed statement (no bytes): give the st2.json relikey-agent cosign wrote")
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return json.loads(decode(raw + "=" * (-len(raw) % 4)))
        except (ValueError, json.JSONDecodeError):
            continue
    sys.exit("refused: the statement's bytes are not a statement: give the st2.json relikey-agent cosign wrote")


def change(statement: dict, targets: list[dict], name: str, entitlements: dict[str, str], profile: str) -> dict:
    says = says_of(statement)
    problems = []
    if says.get("purpose") != "enrolment":
        problems.append(f"the statement's purpose is {says.get('purpose')!r}, not enrolment")
    officer, nodes = says.get("officer", ""), says.get("nodes") or []
    if not ANCHOR.fullmatch(str(officer)):
        problems.append(f"the statement names the officer {officer!r}, not an anchor (op:...): the desk refuses it "
                        "(officer differ); root reads the anchor on the desk's People page and the officer signs again")
    if len(nodes) != 1:
        problems.append(f"the statement names {len(nodes)} nodes: this writes a single-node enrolment")
    signers = {s.get("key") for s in statement.get("signatures") or []}
    for who, key in [("the officer", says.get("officer_key"))] + [("the edge", n.get("enrolment_key")) for n in nodes]:
        if key not in signers:
            problems.append(f"{who} has not signed it (key {str(key)[:16]}...): "
                            + ("the officer cosigns first" if who == "the officer" else "run relikey-agent cosign"))
    if not targets:
        problems.append("the targets file has no targets: the edge would carry none")
    if problems:
        sys.exit("refused, nothing written:\n  " + "\n  ".join(problems))
    node = nodes[0]
    out = {"action": "enrol_edge", "edge_id": says["edge"], "name": name, "officer": officer,
           "officer_key": says["officer_key"], "enrolment_key": node["enrolment_key"], "profile": profile,
           "targets": [{"target": t["name"], "role": t["role"], "entitlement": entitlements.get(t["name"], t["name"])}
                       for t in targets],
           "statement": statement}
    if node.get("unlock_key"):
        out["unlock_key"] = node["unlock_key"]   # the record must hold what the statement signed ("nodes differ")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--statement", required=True, help="the cosigned statement (relikey-agent cosign -out)")
    ap.add_argument("--targets", required=True, help="the edge's targets.yaml")
    ap.add_argument("--name", required=True, help="the edge's name as people see it on the desk")
    ap.add_argument("--entitlement", action="append", default=[], metavar="TARGET=ENTITLEMENT",
                    help="the catalogue entry that grants a target (default: the target's name); repeatable")
    ap.add_argument("--profile", default="basic", choices=("basic", "assured"))
    o = ap.parse_args()
    ents = {}
    for e in o.entitlement:
        t, sep, v = e.partition("=")
        if not (sep and t and v):
            sys.exit(f"--entitlement {e!r}: TARGET=ENTITLEMENT")
        ents[t] = v
    statement = json.loads(Path(o.statement).read_text(encoding="utf-8"))
    targets = (yaml.safe_load(Path(o.targets).read_text(encoding="utf-8")) or {}).get("targets") or []
    unknown = sorted(set(ents) - {t.get("name") for t in targets})
    if unknown:
        sys.exit(f"--entitlement for {', '.join(unknown)}: not a target in {o.targets}")
    print(json.dumps(change(statement, targets, o.name, ents, o.profile), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

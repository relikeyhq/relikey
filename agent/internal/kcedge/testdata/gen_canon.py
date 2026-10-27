"""Canonical-JSON cross vectors from KeyClerk's own encoder (keyclerk.edge.canonical).

Run from a KeyClerk checkout at the pinned tag, with this file's path as the argument:
    python path/to/gen_canon.py > canon.json      (with KeyClerk on PYTHONPATH)
Each case: "input" is JSON text as an edge might receive it (base64 so every byte is exact); "canonical" is what
KeyClerk's canonical() writes for json.loads(input), or null when KeyClerk cannot encode it (a float, NaN, a lone
surrogate). The Go encoder must write the same bytes, and must refuse "input" as signed bytes whenever it differs
from "canonical".
"""
import base64
import json
import sys

from keyclerk import edge

INPUTS = [
    # strings: every control character, quote, backslash, DEL, line separators, non-BMP, combining marks
    '"' + "".join(f"\\u{c:04x}" for c in range(0x20)) + '"',
    '"\\"\\\\/ \\u007f \\u2028 \\u2029 \\u00e9 e\\u0301"',
    '"\\ud83d\\ude00 \\uff61 \\u0000"',
    '"plain ascii"',
    '"\\u0041\\u0042"',
    '"café"',
    # names sort by code point: U+FF61 before U+1F600 (RFC 8785 would put the emoji first)
    '{"\\ud83d\\ude00":1,"\\uff61":2,"a":3,"B":4,"":5,"aa":6,"a\\u0000":7}',
    # numbers
    '[0,-1,1,9223372036854775807,-9223372036854775808,1180591620717411303424,-0]',
    '[true,false,null,[],{},[[]],{"a":{}}]',
    # formatting that canonical() removes
    '{ "b" : 1 , "a" : [ 1 , 2 ] }',
    '{"b":1,"a":2}',
    '{"a":1,"a":2}',
    '﻿{"a":1}',
    # what KeyClerk cannot encode (floats, NaN, lone surrogate)
    '[1.0]', '[1e3]', '[NaN]', '"\\ud800"',
    # a real ceiling shape
    '{"classes":["low"],"edge":"edge-a","format":"kc-edge-ceiling-v1","max_lease_hours":720,"max_offline_hours":12,'
    '"persons":["idp:7c1f-ann"],"ports":[22],"profile":"assured","remote_reach":"off","roles":[],"serial":2,'
    '"signed_at":"2026-10-23T10:00:00Z","targets":["plc-ssh"]}',
]


def case(text):
    raw = text.encode("utf-8")
    try:
        out = base64.b64encode(edge.canonical(json.loads(raw))).decode()
    except (TypeError, ValueError):
        out = None
    return {"input": base64.b64encode(raw).decode(), "canonical": out}


json.dump({"format": "relikey-canon-vectors-v1", "source": "keyclerk.edge.canonical",
           "cases": [case(t) for t in INPUTS]}, sys.stdout, indent=1)
sys.stdout.write("\n")

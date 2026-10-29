# SPDX-License-Identifier: EUPL-1.2
"""Check ReliKey's model: every reference resolves, every flow respects the wrapper rule, nothing names a deployment.

Usage: python tools/check_model.py [--strict]
  --strict also fails on warnings (unpinned digests, open contracts); use it before a release.

Every finding says what is wrong, why it matters and what would fix it (decision 0001, failures say why).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "model"

# Zones a flow may enter the legacy zone from, and the only targets a legacy flow may reach (decision 0002).
INTO_LEGACY_FROM = {"bastion"}
OUT_OF_LEGACY_TO = {"facade"}
OSI_LICENCES = {"Apache-2.0", "MIT", "MPL-2.0", "GPL-3.0", "AGPL-3.0", "BSD-2-Clause", "BSD-3-Clause", "PostgreSQL",
                "EUPL-1.2"}
CONTRACT_STATUS = {"needed", "built", "verified"}

# A deployment, customer or site name in ReliKey's own files breaks decision 0001 point 4. The names themselves are
# held back (tools/publish-private.yaml, never exported): listing them here would publish what the check keeps out.
_PRIVATE = ROOT / "tools" / "publish-private.yaml"
_NAMES = ["vdhome\\.be"] + ((yaml.safe_load(_PRIVATE.read_text(encoding="utf-8")) or {}).get("deployment_names", [])
                            if _PRIVATE.exists() else [])
DEPLOYMENT_NAMES = re.compile(r"\b(" + "|".join(_NAMES) + r")\b", re.IGNORECASE)
NAME_SCAN_GLOBS = ("model/*.yaml", "deploy/**/*", "tools/*.py", "docs/*.md", "docs/decisions/*.md", "README.md")
# Review records quote the context they were written in; they are private and not part of the product text.


class _NoDuplicates(yaml.SafeLoader):
    """YAML keeps the last of two equal keys without a word; in the model that silently drops a fact (the facade's
    upstream was lost that way). Refuse duplicates instead."""


def _mapping(loader, node, deep=False):
    seen = set()
    for k, _ in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in seen:
            raise SystemExit(f"model/{loader.name}: key {key!r} appears twice in one mapping (line {k.start_mark.line + 1}); "
                             f"keep one, YAML would silently use the last")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_NoDuplicates.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load(name: str) -> dict:
    loader = _NoDuplicates((MODEL / name).read_text(encoding="utf-8"))
    loader.name = name
    try:
        return loader.get_single_data() or {}
    finally:
        loader.dispose()


def as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def check_known_gap(prof: dict, ram: int, budget_ram: float, open_ids: set) -> tuple[str | None, str | None]:
    """A profile may record that the edge's memory exceeds its budget, as a known gap with an issue, the release that
    settles it and the open decision it waits on. The gap turns the overrun into a warning only while it is honest:
    a gap without its issue, release or open decision, an edge larger than the gap recorded, or a gap on an edge
    that fits again is an error, so a gap can neither hide a growing overrun nor outlive its cause. Returns
    (error, warning), at most one set."""
    gap = prof["known_gap"]
    where = f"{prof['id']}: known_gap"
    issue, until, waits_on, ceiling = gap.get("issue"), gap.get("until"), gap.get("waits_on"), gap.get("ram_mb")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        return f"{where} names no issue number; a gap is recorded against an open issue, never silently", None
    if not until:
        return f"{where} (#{issue}) names no release that settles it; add `until`", None
    if waits_on not in open_ids:
        return (f"{where} (#{issue}) waits on {waits_on!r}, which is not open in open-decisions.yaml; name the open "
                f"decision it waits on, or settle the gap now that the decision is taken"), None
    if not isinstance(ceiling, int) or isinstance(ceiling, bool):
        return f"{where} (#{issue}) records no ram_mb; record the edge's need when the gap was accepted", None
    if ram <= budget_ram:
        return (f"{where} (#{issue}): the edge needs {ram} MB and fits the {budget_ram:.0f} MB budget again; "
                f"remove the gap"), None
    if ram > ceiling:
        return (f"edge needs {ram} MB memory, more than the {ceiling} MB recorded by {prof['id']}'s known gap "
                f"(#{issue}); the gap covers only what was accepted, so shrink the edge or record the new need"), None
    return None, (f"{prof['id']}: known gap #{issue}, the edge needs {ram} MB memory against a {budget_ram:.0f} MB "
                  f"budget; settled in {until}, after {waits_on}")


def check_footprint(components: dict, footprint: dict, open_ids: set = frozenset()) -> tuple[list[str], list[str]]:
    """Decision 0005: the edge fits every profile within its headroom, on that profile's architecture."""
    errors: list[str] = []
    warnings: list[str] = []
    edge = [c for c in components.values() if c.get("tier") == "edge"]
    headroom = footprint["headroom"]
    ram = sum(c.get("footprint", {}).get("ram_mb", 0) for c in edge)
    disk = sum(c.get("footprint", {}).get("disk_mb", 0) for c in edge)
    for c in edge:
        if "footprint" not in c:
            errors.append(f"{c['id']}: edge component without a footprint estimate; add one so the budget is checked")
        elif not c["footprint"].get("measured"):
            warnings.append(f"{c['id']}: footprint is an estimate; measure it on the reference hardware (R-10)")
    for prof in footprint["profiles"]:
        report = errors if not prof.get("stretch") else warnings
        budget_ram, budget_disk = prof["ram_mb"] * headroom, prof["disk_mb"] * headroom
        # Decision 0009: the local recording store is part of the edge's disk.
        need_disk = disk + prof.get("recording_store_mb", 0)
        if "known_gap" in prof:
            gap_error, gap_warning = check_known_gap(prof, ram, budget_ram, open_ids)
            if gap_error:
                errors.append(gap_error)
            if gap_warning:
                warnings.append(gap_warning)
        elif ram > budget_ram:
            report.append(f"edge needs {ram} MB memory, {prof['id']} allows {budget_ram:.0f} MB "
                          f"({prof['ram_mb']} MB x headroom {headroom}); shrink the edge or drop the profile")
        if need_disk > budget_disk:
            report.append(f"edge needs {need_disk} MB disk incl. its recording store, {prof['id']} allows "
                          f"{budget_disk:.0f} MB; shrink images or the store (offline sessions then stop sooner)")
        for c in edge:
            if prof["arch"] not in c.get("arch", []):
                report.append(f"{c['id']} has no {prof['arch']} build, so the edge cannot run on {prof['id']}")
    return errors, warnings


def check() -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    components = {c["id"]: c for c in load("components.yaml")["components"]}
    flows = load("flows.yaml")["flows"]
    patterns = load("patterns.yaml")["patterns"]
    contracts = load("contracts.yaml")["contracts"]
    open_ids = {d["id"] for d in load("open-decisions.yaml")["open"]}

    for cid, c in components.items():
        if c.get("image"):
            if not c.get("version"):
                errors.append(f"{cid}: image without a version; pin it in components.yaml so upgrades are a "
                              f"deliberate pin change (decision 0001)")
            if c.get("licence") not in OSI_LICENCES:
                errors.append(f"{cid}: licence {c.get('licence')!r} is not on the OSI list ReliKey accepts; "
                              f"add it after review or pick another component")
            if not c.get("digest"):
                warnings.append(f"{cid}: version {c.get('version')} has no digest yet; run the pin step")
        elif c["zone"] == "appliance" and not c.get("optional") and c.get("kind") != "platform":
            if not any(cid in str(d) for d in load("open-decisions.yaml")["open"]):
                errors.append(f"{cid}: appliance component without an image and without an open decision naming it")

    flow_ids = set()
    for f in flows:
        fid = f["id"]
        if fid in flow_ids:
            errors.append(f"{fid}: duplicate flow id")
        flow_ids.add(fid)
        for end in ("from", "to"):
            if f[end] not in components:
                errors.append(f"{fid}: {end} {f[end]!r} is not a component in components.yaml")
        src, dst = components.get(f["from"]), components.get(f["to"])
        if not src or not dst:
            continue
        physical = f.get("medium") == "physical"
        if physical and f["from"] != "person":
            errors.append(f"{fid}: only a person at the machine can be a physical path (pattern P-D); "
                          f"{f['from']!r} is a network component")
        if dst["zone"] == "legacy" and f["from"] not in INTO_LEGACY_FROM and not physical:
            errors.append(f"{fid}: {f['from']} reaches the legacy system directly; only the bastion may "
                          f"(decision 0002). Route it through the bastion or remove the flow")
        if f.get("scope") == "loopback" and not (src.get("tier") == dst.get("tier") in ("edge", "core")):
            errors.append(f"{fid}: a loopback flow must have both ends on one host (the edge, or the core pod); "
                          f"{f['from']} -> {f['to']} crosses hosts")
        if src["zone"] == "legacy" and f["to"] not in OUT_OF_LEGACY_TO:
            errors.append(f"{fid}: the legacy system may only reach the facade (decision 0002); "
                          f"{f['to']!r} would give it a way out")
        if f.get("optional") and not (src.get("optional") or dst.get("optional")):
            warnings.append(f"{fid}: marked optional but both ends are mandatory components")

    # Decision 0008 (RT-5): a loopback-only port must not also be served to a network.
    for f in flows:
        if f.get("scope") != "loopback":
            continue
        for port in as_list(f["port"]):
            for g in flows:
                if g is not f and g["to"] == f["to"] and g.get("scope") != "loopback" and port in as_list(g["port"]):
                    errors.append(f"{g['id']}: reaches {g['to']} port {port}, which {f['id']} declares loopback-only; "
                                  f"serve it on another port or put a filtering proxy in front (decision 0008)")

    # Decision 0005: the core never opens a connection into the edge.
    for f in flows:
        src, dst = components.get(f["from"]), components.get(f["to"])
        if src and dst and src.get("tier") == "core" and dst.get("tier") == "edge":
            errors.append(f"{f['id']}: the core opens a connection into the edge ({f['from']} -> {f['to']}); the edge "
                          f"only connects out (decision 0005). Reverse it so the edge pulls")

    errors_fp, warnings_fp = check_footprint(components, load("footprint.yaml"), open_ids)
    errors += errors_fp
    warnings += warnings_fp

    for p in patterns:
        for step in p["path"]:
            if step not in components:
                errors.append(f"{p['id']}: path step {step!r} is not a component")
        allowed = {(f["from"], f["to"]) for f in flows}
        for a, b in zip(p["path"], p["path"][1:], strict=False):
            if (a, b) not in allowed:
                errors.append(f"{p['id']}: path step {a} -> {b} is not an allowed flow; add the flow or fix the path "
                              f"(a pattern must be walkable, decision 0002)")
        for fid in p["flows"]:
            if fid not in flow_ids:
                errors.append(f"{p['id']}: flow {fid} does not exist in flows.yaml")

    for k in contracts:
        for who in as_list(k["provider"]) + as_list(k["consumer"]):
            if who not in components:
                errors.append(f"{k['id']}: {who!r} is not a component")
        if k["status"] not in CONTRACT_STATUS:
            errors.append(f"{k['id']}: status {k['status']!r} is not one of {sorted(CONTRACT_STATUS)}")
        elif k["status"] != "verified":
            warnings.append(f"{k['id']} ({k['name']}): {k['status']}; an end-to-end test in tests/ makes it verified")

    referenced = set(re.findall(r"\bR-\d\d\b", " ".join(
        p.read_text(encoding="utf-8") for p in list(MODEL.glob("*.yaml")) + list((ROOT / "docs").rglob("*.md")))))
    for rid in sorted(referenced - open_ids):
        decided = any(rid in p.read_text(encoding="utf-8") for p in (ROOT / "docs" / "decisions").glob("0*.md")
                      if "- Status: accepted" in p.read_text(encoding="utf-8"))
        if not decided:
            errors.append(f"{rid} is referenced but neither open in open-decisions.yaml nor named by an accepted decision record; "
                          f"reopen it or record its outcome")

    for glob in NAME_SCAN_GLOBS:
        for path in ROOT.glob(glob):
            if path.is_file() and path.name != "check_model.py":
                for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    if DEPLOYMENT_NAMES.search(line):
                        errors.append(f"{path.relative_to(ROOT)}:{n}: names a deployment; ReliKey names none "
                                      f"(decision 0001). Move it to the deployment's own configuration")
    e2, w2 = check_crypto(components, flow_ids)
    return errors + e2 + check_compose_pins(components), warnings + w2


# An image reference as the shipped compose files write it: name, tag and digest.
PINNED_REF = re.compile(r"^(?P<image>[^@\s]+):(?P<tag>[\w.-]+)@(?P<digest>sha256:[0-9a-f]{64})$")


def check_compose_pins(components: dict) -> list[str]:
    """Decision 0001: what the shipped compose files run is what the model pins. Each upstream image there is a
    component of that tier with the same image, version and digest; otherwise the model describes another release
    than the one deployed (the edge's front ran as a pinned Caddy while the model still had no image for it)."""
    errors: list[str] = []
    for tier in ("core", "edge"):
        path = ROOT / "deploy" / tier / "compose.yaml"
        if not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        for name, svc in ((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("services") or {}).items():
            ref = str((svc or {}).get("image") or "")
            if not ref or ref.startswith("localhost/"):
                continue        # built here (the agent, the fleet, KeyClerk from its tag): no registry pin to match
            m = PINNED_REF.match(ref)
            if not m:
                errors.append(f"{rel} {name}: image {ref!r} is not pinned by tag and digest; pin it, as the model's "
                              f"components are, so a moved tag cannot change what runs (decision 0001)")
                continue
            named = [c for c in components.values() if c.get("tier") == tier and c.get("image") == m["image"]]
            if not named:
                errors.append(f"{rel} {name}: runs {m['image']}, which no {tier} component in components.yaml names; "
                              f"set that component's image, version and digest, or add the component")
                continue
            c = named[0]
            if str(c.get("version")) != m["tag"]:
                errors.append(f"{rel} {name}: runs tag {m['tag']}, component {c['id']} pins version {c.get('version')}; "
                              f"make them the same release (the version is the tag, variant included)")
            if c.get("digest") != m["digest"]:
                errors.append(f"{rel} {name}: runs digest {m['digest'][:19]}..., component {c['id']} pins "
                              f"{str(c.get('digest'))[:19]}...; copy the deployed digest into components.yaml or "
                              f"repin the compose file")
    return errors


KEX = {"hybrid", "classical", "conditional", "none", "n/a", "unverified"}
POLICY = {"required", "visible", "record"}


def check_crypto(components: dict, flow_ids: set) -> tuple[list[str], list[str]]:
    """Decision 0022 A2: every link has a crypto entry, every claim is tied to the pinned version it was checked for."""
    errors: list[str] = []
    warnings: list[str] = []
    crypto = load("crypto.yaml")
    links = crypto.get("links", {})
    for fid in sorted(flow_ids - set(links)):
        errors.append(f"{fid}: no entry in crypto.yaml; say what protects the link (kex, policy, ends) before it ships")
    for fid in sorted(set(links) - flow_ids):
        errors.append(f"crypto.yaml link {fid} is not a flow in flows.yaml; remove it or add the flow")
    for fid, ln in links.items():
        if ln.get("kex") not in KEX:
            errors.append(f"crypto.yaml {fid}: kex {ln.get('kex')!r} is not one of {sorted(KEX)}")
        if ln.get("policy") not in POLICY:
            errors.append(f"crypto.yaml {fid}: policy {ln.get('policy')!r} is not one of {sorted(POLICY)}")
        if ln.get("policy") == "required" and ln.get("kex") in ("conditional", "unverified", "classical"):
            errors.append(f"crypto.yaml {fid}: a required link must be hybrid (or loopback with none); it says "
                          f"{ln.get('kex')!r}. Prove the hybrid or make the link visible")
        if ln.get("kex") == "unverified":
            warnings.append(f"crypto.yaml {fid}: key exchange unverified; the full-stack crypto probe settles it")
    for cid, c in crypto.get("components", {}).items():
        pinned = components.get(cid, {}).get("version")
        if cid not in components:
            errors.append(f"crypto.yaml component {cid!r} is not in components.yaml")
        elif str(c.get("version")) != str(pinned):
            errors.append(f"crypto.yaml {cid}: claims were checked for version {c.get('version')}, the pin is {pinned}; "
                          f"check them again for the new version and update the version there")
        if not c.get("checked"):
            errors.append(f"crypto.yaml {cid}: no 'checked' note; every crypto claim says how it was checked")
    return errors, warnings


def main() -> int:
    strict = "--strict" in sys.argv
    errors, warnings = check()
    for e in errors:
        print(f"ERROR   {e}")
    for w in warnings:
        print(f"WARNING {w}")
    failed = bool(errors) or (strict and bool(warnings))
    print(f"model: {len(errors)} error(s), {len(warnings)} warning(s) -> {'FAIL' if failed else 'OK'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

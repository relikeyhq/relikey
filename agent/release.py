# SPDX-License-Identifier: EUPL-1.2
"""The release half of build.py: `python build.py release | smoke | vex | dist` run these (see build.py's usage).

Kept apart from build.py because build.py is the mutants' harness (mutants.py runs every mutant when it changes);
nothing here changes what a mutant sees. The toolchain, Go environment, tools and the list of binaries stay in build.py.
"""
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build import HERE, LDFLAGS, SBOM_TOOL, binaries, env, go, toolchain  # noqa: E402


def build_into(src: Path, out: Path, version: str) -> dict:
    sums = {}
    for name, goos, arch, extra, module, pkg in binaries():
        r = subprocess.run(["go", "build", "-trimpath", "-buildvcs=true", "-ldflags", f"{LDFLAGS} -X main.version={version}",
                            "-o", str(out / name), pkg], cwd=src.parent / module,
                           env=env(CGO_ENABLED="0", GOOS=goos, GOARCH=arch, **extra), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"build {name}:\n{r.stderr}")
        sums[name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    return sums


def sbom_tool(tmp: Path) -> Path:
    """cyclonedx-gomod, built for this host from its own pinned module, tools/sbom/go.mod."""
    exe = tmp / ("cyclonedx-gomod" + (".exe" if os.name == "nt" else ""))
    r = subprocess.run(["go", "build", "-trimpath", "-o", str(exe), SBOM_TOOL], cwd=HERE / "tools" / "sbom", env=env(),
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"build cyclonedx-gomod:\n{r.stderr}")
    return exe


def normalise_sbom(bom: dict) -> str:
    """The SBOM as release bytes: no timestamp, and no hashes of the SBOM tool's own executable, which differ by the
    host that built it; what is left comes from the binary's module data only. The serial number is a UUIDv5 of that
    content rather than the tool's random one: actions/attest refuses a CycloneDX SBOM without one, and the same
    content keeps the same serial."""
    for t in bom.get("metadata", {}).get("tools", []):
        t.pop("hashes", None)
    bom.pop("serialNumber", None)
    bom.get("metadata", {}).pop("timestamp", None)
    content = json.dumps(bom, sort_keys=True, ensure_ascii=True)
    bom = {"serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'relikey-sbom:' + content)}", **bom}
    return json.dumps(bom, indent=2, ensure_ascii=True) + "\n"


def write_sboms(tool: Path, out: Path, version: str) -> dict:
    """A CycloneDX SBOM beside each binary (NAME.cdx.json), read from the module data the Go build embeds."""
    sums = {}
    for name, goos, arch, extra, _, _ in binaries():
        bom = out / f"{name}.cdx.json"
        # the target's GOOS and GOARCH, or the package URLs would name the host's platform
        r = subprocess.run([str(tool), "bin", "-json", "-noserial", "-notimestamp", "-version", version,
                            "-output", str(bom), name], cwd=out, env=env(GOOS=goos, GOARCH=arch, **extra),
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"SBOM {name}:\n{r.stdout}{r.stderr}")
        bom.write_text(normalise_sbom(json.loads(bom.read_text(encoding="utf-8"))), encoding="utf-8", newline="\n")
        sums[bom.name] = hashlib.sha256(bom.read_bytes()).hexdigest()
    return sums


def release_tag(top) -> str:
    """The release tag on HEAD: vX.Y.Z, the tag release.yml runs on (agent-vX.Y.Z from before 0.1.0 still counts)."""
    return subprocess.run(["git", "describe", "--tags", "--exact-match", "--match", "v[0-9]*", "--match", "agent-v[0-9]*"],
                          cwd=top, capture_output=True, text=True).stdout.strip()


def release():
    toolchain()
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=top, capture_output=True, text=True).stdout.strip()
    tag = release_tag(top)
    if dirty or not tag:
        sys.exit("release builds come from a clean checkout at a vX.Y.Z tag "
                 f"({'uncommitted changes' if dirty else 'no tag on HEAD'})")
    version = tag.removeprefix("agent-")
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tool = sbom_tool(Path(tmp))
        for i in (1, 2):  # two clean checkouts in different paths: -trimpath must make the path irrelevant
            co = Path(tmp) / f"checkout-{i}"
            subprocess.run(["git", "clone", "-q", "--branch", tag, top, str(co)], check=True)
            out = Path(tmp) / f"out-{i}"
            out.mkdir()
            sums = build_into(co / "agent", out, version)
            sums.update(write_sboms(tool, out, version))
            results.append(sums)
        if results[0] != results[1]:
            sys.exit(f"not reproducible:\n{results[0]}\n{results[1]}")
        dist = HERE / "dist"
        shutil.rmtree(dist, ignore_errors=True)
        dist.mkdir()
        for name in results[0]:
            shutil.copy2(Path(tmp) / "out-1" / name, dist / name)
        for name, *_ in binaries():
            (dist / f"{name}.buildinfo").write_text(go("version", "-m", str(dist / name)) + "\n", encoding="utf-8")
    (dist / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sorted(results[0].items())), encoding="utf-8")
    print(f"{version}: binaries and SBOMs reproducible across two checkouts; dist/SHA256SUMS")
    for n, h in sorted(results[0].items()):
        print(f"  {h[:16]}  {n}  {(dist / n).stat().st_size // 1024} KiB")


# (ELF class, e_machine) of each target: 64-bit x86-64 and AArch64, 32-bit ARM
ELF_MACHINE = {"amd64": (2, 62), "arm64": (2, 183), "arm": (1, 40)}
HOST_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
VERSION_ARGS = {"agent": ["version"], "fleet": ["-version"]}


def elf_target(head: bytes):
    """(ELF class, machine) of a little-endian ELF header, or None for anything else."""
    if len(head) < 20 or head[:4] != b"\x7fELF" or head[5] != 1:
        return None
    return head[4], int.from_bytes(head[18:20], "little")


def version_problem(out: str, prog: str, version: str, rev: str) -> str:
    """What is wrong with a binary's version line ("" if nothing): it must name the program, the release's version and
    the tagged commit, and not a modified tree."""
    words = out.split()
    if words[:3] != [prog, version, rev[:12]] or "+dirty" in out:
        return f"reports {out.strip()!r}, expected {prog} {version} {rev[:12]}"
    return ""


def sbom_problem(bom: dict, version: str, sha: str) -> str:
    """What is wrong with a binary's SBOM ("" if nothing): it must describe this release and these exact bytes."""
    meta = bom.get("metadata", {})
    if meta.get("component", {}).get("version") != version:
        return f"SBOM names version {meta.get('component', {}).get('version')!r}, expected {version}"
    props = {p.get("name"): p.get("value") for p in meta.get("properties", [])}
    if props.get("cdx:gomod:binary:hash:SHA-256") != sha:
        return "SBOM describes other bytes than the binary"
    return ""


def run_version(path: Path, module: str) -> tuple[int, str]:
    """Run a built binary's version command: (exit code, output); -1 when it cannot start or hangs."""
    try:
        r = subprocess.run([str(path), *VERSION_ARGS[module]], capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout + r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def smoke_problems(dist: Path, version: str, rev: str, host, run=run_version) -> list[str]:
    """Everything wrong with a release's dist/ (empty when it passes). Each binary must be an ELF file for its target
    and listed in SHA256SUMS with its SBOM; those for the host's architecture must run and report this version and
    commit; each SBOM must describe its binary's exact bytes. At least one binary must have run."""
    sums_file = dist / "SHA256SUMS"
    lines = sums_file.read_text(encoding="utf-8").splitlines() if sums_file.is_file() else []
    sums = {ln.split()[-1]: ln.split()[0] for ln in lines if len(ln.split()) == 2}
    problems, ran = [], 0
    if not version:
        problems.append("no release tag on HEAD")
    for name, _, arch, _, module, _ in binaries():
        path, bom = dist / name, dist / f"{name}.cdx.json"
        if not path.is_file() or not bom.is_file():
            problems.append(f"{name}: binary or SBOM missing")
            continue
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if sums.get(name) != sha or sums.get(bom.name) != hashlib.sha256(bom.read_bytes()).hexdigest():
            problems.append(f"{name}: binary or SBOM not as SHA256SUMS lists it")
        if elf_target(data[:64]) != ELF_MACHINE[arch]:
            problems.append(f"{name}: not an ELF binary for {arch}")
        if arch == host:
            ran += 1
            rc, out = run(path, module)
            if rc != 0:
                problems.append(f"{name}: does not run (exit {rc}): {out.strip()[:200]}")
            elif p := version_problem(out, name.rsplit("-linux-", 1)[0], version, rev):
                problems.append(f"{name}: {p}")
        if p := sbom_problem(json.loads(bom.read_text(encoding="utf-8")), version, sha):
            problems.append(f"{name}: {p}")
    if not ran:
        problems.append("no binary ran: the smoke test needs a linux/amd64 or linux/arm64 host")
    return problems


def smoke():
    """After `release`, on the release host: the binaries in dist/ run, report the release, and match their SBOMs."""
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    version = release_tag(top).removeprefix("agent-")
    rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=top, capture_output=True, text=True).stdout.strip()
    host = HOST_ARCH.get(platform.machine().lower()) if sys.platform == "linux" else None
    problems = smoke_problems(HERE / "dist", version, rev, host)
    if problems:
        sys.exit("smoke test failed:\n  " + "\n  ".join(problems))
    print(f"{version}: smoke test passed (the {host} binaries ran; every ELF target, sum and SBOM checked)")


# The release's VEX (#30): for each known vulnerability in a module or the standard library a binary is built from,
# whether that binary calls the vulnerable code, as govulncheck's reachability analysis finds it at release time.
VEX_FILE = "relikey.openvex.json"
REPOSITORY = "relikeyhq/relikey"


def vuln_tool(tmp: Path) -> Path:
    """govulncheck from tools/go.mod, built for this host: `go tool` under a target's GOOS and GOARCH would build it
    for that target and could not run it here."""
    exe = tmp / ("govulncheck" + (".exe" if os.name == "nt" else ""))
    r = subprocess.run(["go", "build", f"-modfile={HERE / 'tools' / 'go.mod'}", "-trimpath", "-o", str(exe),
                        "golang.org/x/vuln/cmd/govulncheck"], cwd=HERE, env=env(), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"build govulncheck:\n{r.stderr}")
    return exe


def govulncheck_version() -> str:
    """The golang.org/x/vuln version tools/go.mod pins, which the VEX names as its tooling."""
    found = re.search(r"^\s+golang\.org/x/vuln (v\S+)", (HERE / "tools" / "go.mod").read_text(encoding="utf-8"), re.M)
    return found.group(1) if found else "unknown"


def vex_product(sbom: dict, sha: str) -> dict:
    """A binary as a VEX product: the package URL its SBOM names it by (write_sboms: metadata.component.purl, with
    the target's goos and goarch) and its SHA-256, the two keys a scanner joins VEX, SBOM and file on."""
    purl = sbom.get("metadata", {}).get("component", {}).get("purl", "")
    return {"@id": purl, "identifiers": {"purl": purl}, "hashes": {"sha-256": sha}}


def vex_document(version: str, timestamp: str, products: dict, reports: dict, tooling: str) -> dict:
    """One OpenVEX document from govulncheck's openvex output for each binary. products maps a binary's name to its
    product (the package URL its SBOM's metadata component carries, so a scanner joins VEX to SBOM, and the binary's
    SHA-256); reports maps the name to govulncheck's document for that binary's module and target. The same verdict
    on the same vulnerability in several binaries is one statement listing them all. Nothing here depends on the host,
    the clock or the order govulncheck reports in: the bytes follow from the release and the vulnerability data."""
    merged = {}
    for name in sorted(reports):
        for st in reports[name].get("statements") or []:
            verdict = {k: st[k] for k in ("vulnerability", "status", "justification", "impact_statement") if k in st}
            entry = merged.setdefault(json.dumps(verdict, sort_keys=True), {**verdict, "products": {}})
            product = dict(products[name])
            subs = sorted({s["@id"] for p in st.get("products", []) for s in p.get("subcomponents", [])})
            if subs:   # the module (or stdlib) at the version that carries the vulnerability
                product["subcomponents"] = [{"@id": s} for s in subs]
            entry["products"][product["@id"]] = product
    statements = []
    def order(k):
        return merged[k]["vulnerability"].get("name", ""), merged[k].get("status", ""), k
    for key in sorted(merged, key=order):
        e = merged[key]
        statements.append({"vulnerability": e["vulnerability"],
                           "products": [e["products"][p] for p in sorted(e["products"])],
                           **{k: e[k] for k in ("status", "justification", "impact_statement") if k in e}})
    return {"@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://github.com/{REPOSITORY}/releases/download/{version}/{VEX_FILE}",
            "author": "ReliKey release build", "timestamp": timestamp, "version": 1, "tooling": tooling,
            "statements": statements}


def vex_refusal(doc: dict) -> str:
    """Why this VEX cannot be published ("" if it can): a statement that is not `not_affected` means govulncheck found
    the vulnerable code called (or a verdict this build does not know), and a release must not ship that."""
    bad = [f"  {st['vulnerability'].get('name', '?')} ({', '.join(st['vulnerability'].get('aliases', [])) or '-'}):"
           f" {st.get('status')} in {', '.join(p['@id'] for p in st['products'])}"
           for st in doc["statements"] if st.get("status") != "not_affected"]
    if not bad:
        return ""
    return ("VEX refused: govulncheck finds vulnerable code called in this release, so its VEX cannot say ReliKey "
            "is not affected:\n" + "\n".join(bad) + "\nNext: on main, move each module an advisory names to its fixed "
            "version (the Go toolchain for the standard library; `python agent/build.py vuln` shows the call path and "
            "the fix), merge with CI green, and tag the next version; this tag stays, release tags never move "
            "(docs/publishing.md).")


def sums_with(text: str, name: str, sha: str) -> str:
    """SHA256SUMS with NAME's line added or replaced, sorted by file name as `release` writes it."""
    sums = {ln.split()[-1]: ln.split()[0] for ln in text.splitlines() if len(ln.split()) == 2}
    sums[name] = sha
    return "".join(f"{h}  {n}\n" for n, h in sorted(sums.items()))


def vex():
    """After `release` (and `smoke`): the release's VEX in dist/, listed in SHA256SUMS so the provenance attestation
    and the keyless signatures cover it."""
    toolchain()
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    tag = release_tag(top)
    if not tag:
        sys.exit("vex describes a release: run it at a vX.Y.Z tag, after `python agent/build.py release` "
                 "(no tag on HEAD)")
    version = tag.removeprefix("agent-")
    # the tagged commit's time, not the clock: building the VEX twice for one release gives the same bytes
    ct = subprocess.run(["git", "log", "-1", "--format=%ct", "HEAD"], cwd=top, capture_output=True, text=True).stdout
    timestamp = datetime.datetime.fromtimestamp(int(ct), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dist, products, reports = HERE / "dist", {}, {}
    tmp = tempfile.TemporaryDirectory()
    govulncheck = vuln_tool(Path(tmp.name))
    for name, goos, arch, extra, module, _ in binaries():
        bom, binary = dist / f"{name}.cdx.json", dist / name
        if not bom.is_file() or not binary.is_file():
            sys.exit(f"{name}: binary or SBOM missing in agent/dist/; the VEX names each binary as its SBOM does, so "
                     "run `python agent/build.py release` first")
        sbom = json.loads(bom.read_text(encoding="utf-8"))
        found = sbom.get("metadata", {}).get("component", {}).get("version")
        if found != version:
            sys.exit(f"{bom.name} describes version {found!r}, HEAD is tagged {tag}: rebuild agent/dist/ with "
                     "`python agent/build.py release` at this tag")
        products[name] = vex_product(sbom, hashlib.sha256(binary.read_bytes()).hexdigest())
        if not products[name]["@id"]:
            sys.exit(f"{bom.name} has no metadata.component.purl to name {name} by: rebuild agent/dist/ with "
                     "`python agent/build.py release`")
        # the binary's own target: what is reachable can differ by GOOS and GOARCH
        r = subprocess.run([str(govulncheck), "-format", "openvex", "./..."], cwd=HERE.parent / module,
                           env=env(GOOS=goos, GOARCH=arch, **extra), capture_output=True, text=True)
        try:
            reports[name] = json.loads(r.stdout) if r.returncode == 0 else None
        except json.JSONDecodeError:
            reports[name] = None
        if reports[name] is None:
            sys.exit(f"govulncheck for {name} ({module}, {goos}/{arch}) failed (exit {r.returncode}):\n"
                     f"{r.stderr.strip()}\nIt fetches the vulnerability database from vuln.go.dev: check the network, "
                     "then run `python agent/build.py vex` again")
    tmp.cleanup()
    tooling = f"govulncheck {govulncheck_version()} (golang.org/x/vuln)"
    doc = vex_document(version, timestamp, products, reports, tooling)
    if problem := vex_refusal(doc):
        sys.exit(problem)
    out = dist / VEX_FILE
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    sums = dist / "SHA256SUMS"
    sums.write_text(sums_with(sums.read_text(encoding="utf-8") if sums.is_file() else "", VEX_FILE,
                              hashlib.sha256(out.read_bytes()).hexdigest()), encoding="utf-8", newline="\n")
    print(f"{version}: {len(doc['statements'])} VEX statements, none affected, for {len(products)} binaries; "
          f"dist/{VEX_FILE} added to dist/SHA256SUMS")


def dist():
    """A development build of the three binaries into dist/ (not a release: no tag needed, not compared)."""
    toolchain()
    rev = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    out = HERE / "dist"
    out.mkdir(exist_ok=True)
    for n, h in sorted(build_into(HERE, out, f"dev-{rev}").items()):
        print(f"  {h[:16]}  {n}")

# SPDX-License-Identifier: EUPL-1.2
"""Checks and release builds for the edge agent, by docs/go-engineering.md.

    python build.py check      gofmt, vet (three targets), staticcheck, tests, mutants   (every change)
                               --changed BASE: only the mutants a change since BASE can affect (a pull request)
                               --no-mutants: none (CI runs them as parallel jobs on main and nightly)
    python build.py mutants    every mutant; --shard I/N runs part I of N (see mutants.py)
    python build.py race       go test -race (needs cgo and a C compiler: Linux amd64/arm64 only)
    python build.py vuln       govulncheck on the source
    python build.py dist       a development build of the three binaries into dist/ (for images and labs)
    python build.py release    the five static binaries, built twice from a clean tagged checkout and compared;
                               dist/ gets the binaries, a CycloneDX SBOM and the build info of each, and SHA256SUMS
    python build.py smoke      after release: each binary is an ELF file for its target, those this host can run
                               report the release's version and commit, and each SBOM describes its binary

The Go toolchain must be exactly the one go.mod names: GOTOOLCHAIN=local ignores the toolchain line, so this script
checks `go env GOVERSION` itself (GE-9). Developer tools come from tools/go.mod, never from the agent's module; the
SBOM tool from its own tools/sbom/go.mod, so its dependencies never move the gate tools' versions.
"""
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGETS = [("linux", "amd64", {}), ("linux", "arm64", {}), ("linux", "arm", {"GOARM": "7,hardfloat"})]
CORE_TARGETS = [("linux", "amd64", {}), ("linux", "arm64", {})]   # the core never runs on armv7
LDFLAGS = "-s -w -buildid="
SBOM_TOOL = "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod"   # pinned in tools/sbom/go.mod


def env(**extra):
    e = {k: v for k, v in os.environ.items() if not k.startswith("GO") or k in ("GOPATH", "GOCACHE", "GOMODCACHE")}
    e.update(GOTOOLCHAIN="local", GOFLAGS="-mod=readonly", **extra)
    return e


FLEET = HERE.parent / "fleet"   # the fleet service's own module (decision 0026)


def go(*args, check=True, cwd=None, **extra):
    r = subprocess.run(["go", *args], cwd=cwd or HERE, env=env(**extra), capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"go {' '.join(args)} failed:\n{r.stdout}{r.stderr}")
    return r.stdout.strip()


def toolchain():
    want = re.search(r"^toolchain (go[\d.]+)$", (HERE / "go.mod").read_text(), re.M).group(1)
    have = go("env", "GOVERSION")
    if have != want:
        sys.exit(f"toolchain {have}, go.mod names {want}: install {want} (golang.org/dl) and put it first on PATH")
    print(f"toolchain {have}")


def tool(name, *args, cwd=None):
    r = subprocess.run(["go", "tool", f"-modfile={HERE / 'tools' / 'go.mod'}", name, *args], cwd=cwd or HERE, env=env(),
                       capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def check(*args):
    if args not in ((), ("--no-mutants",)) and not (len(args) == 2 and args[0] == "--changed"):
        sys.exit(__doc__)
    toolchain()
    unformatted = subprocess.run(["gofmt", "-l", ".", str(FLEET)], cwd=HERE, capture_output=True, text=True).stdout.strip()
    if unformatted:
        sys.exit("gofmt: " + unformatted)
    for goos, arch, extra in [("windows", "amd64", {}), *TARGETS]:
        go("vet", "./...", GOOS=goos, GOARCH=arch, **extra)
    for goos, arch, extra in [("windows", "amd64", {}), *CORE_TARGETS]:
        go("vet", "./...", cwd=FLEET, GOOS=goos, GOARCH=arch, **extra)
    print("gofmt, vet: windows/amd64, linux/amd64, linux/arm64, linux/arm (v7)")
    for where in (HERE, FLEET):
        rc, out = tool("staticcheck", "./...", cwd=where)
        if rc != 0:
            sys.exit(f"staticcheck ({where.name}):\n" + out)
    print("staticcheck: clean")
    go("test", "-count=1", "-shuffle=on", "./...")
    # the anchor ceremony in a real browser, where Python Playwright is installed (fleet/internal/page/browser_test.go)
    browser = importlib.util.find_spec("playwright") is not None
    # the edge installer's enrolment against the fleet, where Python is 3.13 or later (the CA pin reads the chain the
    # fleet presents) and has cryptography (fleet/internal/fleet)
    installer = sys.version_info >= (3, 13) and importlib.util.find_spec("cryptography") is not None
    go("test", "-count=1", "-shuffle=on", "./...", cwd=FLEET,
       **({"RELIKEY_BROWSER": "1"} if browser else {}), **({"RELIKEY_INSTALLER": "1"} if installer else {}),
       **({"RELIKEY_PYTHON": sys.executable} if browser or installer else {}))
    print("tests: pass" + ("" if browser else " (the browser ceremony skipped: no Python Playwright here)")
          + ("" if installer else " (the installer's enrolment skipped: needs Python 3.13 or later with cryptography)"))
    if args != ("--no-mutants",):
        mutants(*args)


def mutants(*args):
    """mutants.py with these arguments (--changed BASE, --shard I/N) in this script's Go environment."""
    r = subprocess.run([sys.executable, "mutants.py", *args], cwd=HERE, env=env(), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("mutants:\n" + r.stdout + r.stderr)
    print("\n".join(line for line in r.stdout.strip().splitlines() if not line.startswith("killed ")))


def race():
    toolchain()
    go("test", "-race", "-count=1", "-shuffle=on", "./...", CGO_ENABLED="1")
    print("race: pass")


def vuln():
    toolchain()
    rc, out = tool("govulncheck", "./...")
    print(out.splitlines()[-1] if out else "")
    if rc != 0:
        sys.exit(out)


def binaries():
    """Each released binary: its file name, target and the module and package it is built from."""
    for goos, arch, extra in TARGETS:
        name = f"relikey-agent-{goos}-{arch}" + ("v7" if arch == "arm" else "")
        yield name, goos, arch, extra, "agent", "./cmd/relikey-agent"
    for goos, arch, extra in CORE_TARGETS:   # the fleet service runs in the core (decision 0026)
        yield f"relikey-fleet-{goos}-{arch}", goos, arch, extra, "fleet", "./cmd/relikey-fleet"


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
    """The SBOM as release bytes: no serial number or timestamp (the tool omits them), and no hashes of the SBOM tool's
    own executable, which differ by the host that built it; what is left comes from the binary's module data only."""
    for t in bom.get("metadata", {}).get("tools", []):
        t.pop("hashes", None)
    bom.pop("serialNumber", None)
    bom.get("metadata", {}).pop("timestamp", None)
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


def dist():
    """A development build of the three binaries into dist/ (not a release: no tag needed, not compared)."""
    toolchain()
    rev = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    out = HERE / "dist"
    out.mkdir(exist_ok=True)
    for n, h in sorted(build_into(HERE, out, f"dev-{rev}").items()):
        print(f"  {h[:16]}  {n}")


if __name__ == "__main__":
    cmds = {"check": check, "race": race, "vuln": vuln, "release": release, "smoke": smoke, "dist": dist,
            "mutants": lambda *a: (toolchain(), mutants(*a))}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds or (len(sys.argv) > 2 and sys.argv[1] not in ("check", "mutants")):
        sys.exit(__doc__)
    cmds[sys.argv[1]](*sys.argv[2:])

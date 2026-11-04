# SPDX-License-Identifier: EUPL-1.2
"""Checks and release builds for the edge agent, by docs/go-engineering.md.

    python build.py check      gofmt, vet (three targets), staticcheck, tests, mutants   (every change)
                               --changed BASE: only the mutants a change since BASE can affect (a pull request)
                               --no-mutants: none (CI runs them as parallel jobs on main and nightly)
    python build.py mutants    every mutant; --shard I/N runs part I of N (see mutants.py)
    python build.py race       go test -race (needs cgo and a C compiler: Linux amd64/arm64 only)
    python build.py vuln       govulncheck on the source of the agent and the fleet service
    python build.py dist       a development build of the three binaries into dist/ (for images and labs)
    python build.py release    the five static binaries, built twice from a clean tagged checkout and compared;
                               dist/ gets the binaries, a CycloneDX SBOM and the build info of each, and SHA256SUMS
    python build.py smoke      after release: each binary is an ELF file for its target, those this host can run
                               report the release's version and commit, and each SBOM describes its binary
    python build.py vex        after release: one OpenVEX document, dist/relikey.openvex.json, from govulncheck run
                               on each binary's module for its target, added to SHA256SUMS; refuses if any is affected

The Go toolchain must be exactly the one go.mod names: GOTOOLCHAIN=local ignores the toolchain line, so this script
checks `go env GOVERSION` itself (GE-9). Developer tools come from tools/go.mod, never from the agent's module; the
SBOM tool from its own tools/sbom/go.mod, so its dependencies never move the gate tools' versions.

release, smoke, vex and dist live in release.py: this file is the mutants' harness (mutants.py), so a change here
runs every mutant, and the release steps change nothing a mutant can see.
"""
import importlib.util
import os
import re
import subprocess
import sys
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
    # go mod tidy drops the toolchain line when the go line names the same release
    mod = (HERE / "go.mod").read_text()
    found = re.search(r"^toolchain go([\d.]+)$", mod, re.M) or re.search(r"^go (\d+\.\d+\.\d+)$", mod, re.M)
    want = "go" + found.group(1)
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
    """govulncheck on each module a released binary is built from (the agent and the fleet service)."""
    toolchain()
    for module in sorted({b[4] for b in binaries()}):
        rc, out = tool("govulncheck", "./...", cwd=HERE.parent / module)
        print(f"{module}: " + (out.splitlines()[-1] if out else ""))
        if rc != 0:
            sys.exit(f"{module}:\n{out}")


def binaries():
    """Each released binary: its file name, target and the module and package it is built from."""
    for goos, arch, extra in TARGETS:
        name = f"relikey-agent-{goos}-{arch}" + ("v7" if arch == "arm" else "")
        yield name, goos, arch, extra, "agent", "./cmd/relikey-agent"
    for goos, arch, extra in CORE_TARGETS:   # the fleet service runs in the core (decision 0026)
        yield f"relikey-fleet-{goos}-{arch}", goos, arch, extra, "fleet", "./cmd/relikey-fleet"


if __name__ == "__main__":
    def released(name):
        """A release command, from release.py (outside the mutants' harness, so a change to it runs no mutant)."""
        def run(*a):
            sys.path.insert(0, str(HERE))
            import release
            getattr(release, name)(*a)
        return run
    cmds = {"check": check, "race": race, "vuln": vuln, "mutants": lambda *a: (toolchain(), mutants(*a)),
            **{n: released(n) for n in ("release", "smoke", "vex", "dist")}}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds or (len(sys.argv) > 2 and sys.argv[1] not in ("check", "mutants")):
        sys.exit(__doc__)
    cmds[sys.argv[1]](*sys.argv[2:])

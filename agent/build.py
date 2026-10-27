# SPDX-License-Identifier: EUPL-1.2
"""Checks and release builds for the edge agent, by docs/go-engineering.md.

    python build.py check      gofmt, vet (three targets), staticcheck, tests, mutants   (every change)
    python build.py race       go test -race (needs cgo and a C compiler: Linux amd64/arm64 only)
    python build.py vuln       govulncheck on the source
    python build.py dist       a development build of the three binaries into dist/ (for images and labs)
    python build.py release    three static binaries, built twice from a clean tagged checkout and compared;
                               dist/ gets the binaries, SHA256SUMS and the build info of each

The Go toolchain must be exactly the one go.mod names: GOTOOLCHAIN=local ignores the toolchain line, so this script
checks `go env GOVERSION` itself (GE-9). Developer tools come from tools/go.mod, never from the agent's module.
"""
import hashlib
import importlib.util
import os
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


def check():
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
    go("test", "-count=1", "-shuffle=on", "./...", cwd=FLEET,
       **({"RELIKEY_BROWSER": "1", "RELIKEY_PYTHON": sys.executable} if browser else {}))
    print("tests: pass" + ("" if browser else " (the browser ceremony skipped: no Python Playwright here)"))
    r = subprocess.run([sys.executable, "mutants.py"], cwd=HERE, env=env(), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("mutants:\n" + r.stdout)
    print(r.stdout.strip().splitlines()[-1])


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


def build_into(src: Path, out: Path, version: str) -> dict:
    sums = {}
    for goos, arch, extra in TARGETS:
        name = f"relikey-agent-{goos}-{arch}" + ("v7" if arch == "arm" else "")
        r = subprocess.run(["go", "build", "-trimpath", "-buildvcs=true", "-ldflags", f"{LDFLAGS} -X main.version={version}",
                            "-o", str(out / name), "./cmd/relikey-agent"], cwd=src,
                           env=env(CGO_ENABLED="0", GOOS=goos, GOARCH=arch, **extra), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"build {name}:\n{r.stderr}")
        sums[name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    for goos, arch, extra in CORE_TARGETS:   # the fleet service runs in the core (decision 0026)
        name = f"relikey-fleet-{goos}-{arch}"
        r = subprocess.run(["go", "build", "-trimpath", "-buildvcs=true", "-ldflags", LDFLAGS,
                            "-o", str(out / name), "./cmd/relikey-fleet"], cwd=src.parent / "fleet",
                           env=env(CGO_ENABLED="0", GOOS=goos, GOARCH=arch, **extra), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"build {name}:\n{r.stderr}")
        sums[name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    return sums


def release():
    toolchain()
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=top, capture_output=True, text=True).stdout.strip()
    tag = subprocess.run(["git", "describe", "--tags", "--exact-match", "--match", "agent-v*"], cwd=top,
                         capture_output=True, text=True).stdout.strip()
    if dirty or not tag:
        sys.exit("release builds come from a clean checkout at an agent-vX.Y.Z tag "
                 f"({'uncommitted changes' if dirty else 'no tag on HEAD'})")
    version = tag.removeprefix("agent-")
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for i in (1, 2):  # two clean checkouts in different paths: -trimpath must make the path irrelevant
            co = Path(tmp) / f"checkout-{i}"
            subprocess.run(["git", "clone", "-q", "--branch", tag, top, str(co)], check=True)
            (Path(tmp) / f"out-{i}").mkdir()
            results.append(build_into(co / "agent", Path(tmp) / f"out-{i}", version))
        if results[0] != results[1]:
            sys.exit(f"not reproducible:\n{results[0]}\n{results[1]}")
        dist = HERE / "dist"
        shutil.rmtree(dist, ignore_errors=True)
        dist.mkdir()
        for name in results[0]:
            shutil.copy2(Path(tmp) / "out-1" / name, dist / name)
            (dist / f"{name}.buildinfo").write_text(go("version", "-m", str(dist / name)) + "\n", encoding="utf-8")
    (dist / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sorted(results[0].items())), encoding="utf-8")
    print(f"{version}: reproducible across two checkouts; dist/SHA256SUMS")
    for n, h in sorted(results[0].items()):
        print(f"  {h[:16]}  {n}  {(dist / n).stat().st_size // 1024} KiB")


def dist():
    """A development build of the three binaries into dist/ (not a release: no tag needed, not compared)."""
    toolchain()
    rev = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    out = HERE / "dist"
    out.mkdir(exist_ok=True)
    for n, h in sorted(build_into(HERE, out, f"dev-{rev}").items()):
        print(f"  {h[:16]}  {n}")


if __name__ == "__main__":
    cmds = {"check": check, "race": race, "vuln": vuln, "release": release, "dist": dist}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__)
    cmds[sys.argv[1]]()

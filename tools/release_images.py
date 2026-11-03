#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""The release images: the agent and fleet images, one multi-platform image each, from the binaries in agent/dist/.

  python tools/release_images.py build                       # every platform, nothing pushed (pull requests)
  python tools/release_images.py push --version X.Y.Z --registry ghcr.io/OWNER --digests FILE

Each image is built with `docker buildx` from the repository root, for the platforms its binaries are built for
(agent/build.py: TARGETS for the agent, CORE_TARGETS for the fleet service), so the binaries and the images cannot
drift apart. The Dockerfiles only copy files for the target platform (their busybox stage runs on the build
platform), so no emulation is needed. `push` tags the image with the version only and writes
{"relikey-agent": "sha256:...", ...} to FILE; release.yml then attests, signs and lists each image by that digest.
"""
import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _build_py():
    spec = importlib.util.spec_from_file_location("agent_build", ROOT / "agent" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def platform(goos: str, arch: str, extra: dict) -> str:
    """A build.py target as a buildx platform: ("linux", "arm", {"GOARM": "7,hardfloat"}) -> linux/arm/v7."""
    if arch == "arm":
        return f"{goos}/arm/v{extra['GOARM'].split(',')[0]}"
    return f"{goos}/{arch}"


def images() -> dict[str, dict]:
    """Image name -> its Dockerfile and platforms."""
    b = _build_py()
    return {
        "relikey-agent": {"file": "deploy/edge/Dockerfile.agent", "platforms": [platform(*t) for t in b.TARGETS]},
        "relikey-fleet": {"file": "deploy/core/Dockerfile.fleet", "platforms": [platform(*t) for t in b.CORE_TARGETS]},
    }


def binary(name: str, plat: str) -> str:
    """The file in agent/dist/ a Dockerfile copies for a platform (TARGETARCH plus TARGETVARIANT)."""
    _, arch, *variant = plat.split("/")
    return f"agent/dist/{name}-linux-{arch}{variant[0] if variant else ''}"


def command(name: str, spec: dict, ref: str | None, metadata: Path | None) -> list[str]:
    cmd = ["docker", "buildx", "build", "--file", spec["file"], "--platform", ",".join(spec["platforms"]),
           "--provenance=false", "--sbom=false"]   # provenance and signatures come from release.yml, by digest
    if ref:
        cmd += ["--tag", ref, "--push", "--metadata-file", str(metadata)]
    return [*cmd, "."]


def missing_binaries() -> list[str]:
    return [binary(n, p) for n, s in images().items() for p in s["platforms"] if not (ROOT / binary(n, p)).is_file()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    p = sub.add_parser("push")
    p.add_argument("--version", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--digests", type=Path, required=True)
    a = ap.parse_args(argv)
    if missing := missing_binaries():
        print("missing in agent/dist/ (run python agent/build.py dist or release first): " + ", ".join(missing),
              file=sys.stderr)
        return 1
    digests = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name, spec in images().items():
            ref = f"{a.registry}/{name}:{a.version}" if a.cmd == "push" else None
            meta = Path(tmp) / f"{name}.json"
            subprocess.run(command(name, spec, ref, meta), cwd=ROOT, check=True)
            if ref:
                digests[name] = json.loads(meta.read_text(encoding="utf-8"))["containerimage.digest"]
    if a.cmd == "push":
        a.digests.write_text(json.dumps(digests, indent=1) + "\n", encoding="utf-8")
        print(json.dumps(digests))
    return 0


if __name__ == "__main__":
    sys.exit(main())

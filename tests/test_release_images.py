# SPDX-License-Identifier: EUPL-1.2
"""The release images are built for exactly the platforms the binaries are built for, from the binaries build.py
names, without emulation; release.yml pushes, attests and signs them by digest and lists the digests (#29)."""
import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("release_images", ROOT / "tools" / "release_images.py")
ri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ri)
spec = importlib.util.spec_from_file_location("agent_build", ROOT / "agent" / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def test_platforms_follow_the_build_targets():
    imgs = ri.images()
    assert imgs["relikey-agent"]["platforms"] == ["linux/amd64", "linux/arm64", "linux/arm/v7"]
    assert imgs["relikey-fleet"]["platforms"] == ["linux/amd64", "linux/arm64"]


def test_each_platform_copies_a_binary_build_py_makes():
    made = {f"agent/dist/{name}" for name, *_ in build.binaries()}
    wanted = {ri.binary(n, p) for n, s in ri.images().items() for p in s["platforms"]}
    assert wanted <= made, wanted - made


def test_dockerfiles_need_no_emulation():
    for s in ri.images().values():
        text = (ROOT / s["file"]).read_text(encoding="utf-8")
        froms = re.findall(r"^FROM .*$", text, re.M)
        # every stage that runs a command runs on the build platform; the image itself is scratch plus copies
        assert all("--platform=$BUILDPLATFORM" in f or f.startswith("FROM scratch") for f in froms), froms
        final = text[text.rindex("FROM scratch"):]
        assert "RUN " not in final and "${TARGETARCH}" in final


def test_build_mode_pushes_nothing():
    cmd = ri.command("relikey-agent", ri.images()["relikey-agent"], None, None)
    assert "--push" not in cmd and "--tag" not in cmd
    assert "linux/amd64,linux/arm64,linux/arm/v7" in cmd


def test_push_mode_tags_the_version_only():
    cmd = ri.command("relikey-fleet", ri.images()["relikey-fleet"], "ghcr.io/o/relikey-fleet:0.3.0", Path("m.json"))
    assert cmd[cmd.index("--tag") + 1] == "ghcr.io/o/relikey-fleet:0.3.0"
    assert "--push" in cmd and "--metadata-file" in cmd and cmd.count("--tag") == 1


def test_missing_binaries_refuse(tmp_path, monkeypatch):
    imgs = ri.images()
    monkeypatch.setattr(ri, "images", lambda: imgs)
    monkeypatch.setattr(ri, "ROOT", tmp_path)   # an empty tree: no agent/dist/
    assert ri.main(["build"]) == 1


def test_release_workflow_signs_and_lists_images_by_digest():
    workflows = ROOT / ".github" / "workflows"
    jobs = yaml.safe_load((workflows / "release.yml").read_text(encoding="utf-8"))["jobs"]
    built = yaml.safe_load((workflows / "release-build.yml").read_text(encoding="utf-8"))
    job = built["jobs"]["images"]   # in the reusable build workflow (#28), its digests passed out to the release
    assert built[True]["workflow_call"]["outputs"]["agent"]["value"] == "${{ jobs.images.outputs.agent }}"
    assert job["permissions"] == {"contents": "read", "packages": "write", "id-token": "write",
                                  "attestations": "write"}
    steps = "\n".join(str(s.get("run", "")) + str(s.get("uses", "")) + str(s.get("with", "")) for s in job["steps"])
    assert "release_images.py push" in steps
    assert "cosign sign --yes" in steps
    assert "attest-build-provenance" in steps and "push-to-registry" in steps
    assert jobs["github-release"]["needs"] == "build"
    release = "\n".join(str(s.get("run", "")) + str(s.get("env", "")) for s in jobs["github-release"]["steps"])
    assert "needs.build.outputs.agent" in release
    assert "digests" in release   # the release notes list each image's digest


def test_pull_requests_build_the_images():
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = "\n".join(str(s.get("run", "")) for s in ci["jobs"]["images"]["steps"])
    assert "release_images.py build" in steps

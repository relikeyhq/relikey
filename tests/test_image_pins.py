# SPDX-License-Identifier: EUPL-1.2
"""The image files pin every base image by digest, and Dependabot watches the directories they sit in. The files are
named Dockerfile.* because Dependabot's docker ecosystem only reads that name. The installers run the busybox their
image file pins, read from that file, never a tag of their own."""
import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
IMAGE_FILES = sorted((ROOT / "deploy").glob("*/Dockerfile.*"))
FROM = re.compile(r"^FROM\s+(?!scratch\b)(\S+)", re.M | re.I)


def test_image_files_exist():
    assert [p.parent.name for p in IMAGE_FILES] == ["core", "edge"]


@pytest.mark.parametrize("path", IMAGE_FILES, ids=lambda p: p.parent.name)
def test_base_images_pinned_by_digest(path):
    bases = FROM.findall(path.read_text(encoding="utf-8"))
    assert bases, "no base image found"
    for image in bases:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{path.name}: {image} is not pinned by digest"


def test_dependabot_watches_the_image_directories():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    watched = {d for u in cfg["updates"] if u["package-ecosystem"] == "docker" for d in u["directories"]}
    assert watched == {"/deploy/" + p.parent.name for p in IMAGE_FILES}


DEPLOY_FILES = sorted(p for p in (ROOT / "deploy").rglob("*")
                      if p.is_file() and not {"secrets", "__pycache__"} & set(p.parts))
BUSYBOX_REF = re.compile(r"busybox:\w[\w.-]*(?:@sha256:\w*)?")   # an image reference, not the installers' pattern
INSTALLERS = {"core": ("install.py", "Dockerfile.fleet"), "edge": ("install.py", "Dockerfile.agent")}


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(f"relikey_{path.parent.name}_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_busybox_by_tag_in_deploy():
    bad = [f"{p.relative_to(ROOT).as_posix()}: {ref}" for p in DEPLOY_FILES
           for ref in BUSYBOX_REF.findall(p.read_text(encoding="utf-8"))
           if not re.fullmatch(r"busybox:[\w.-]+@sha256:[0-9a-f]{64}", ref)]
    assert not bad, "busybox by tag, not by digest: " + "; ".join(bad)


@pytest.mark.parametrize("part", sorted(INSTALLERS))
def test_installer_runs_the_busybox_its_image_file_pins(part):
    script, image_file = INSTALLERS[part]
    base = [b for b in FROM.findall((ROOT / "deploy" / part / image_file).read_text(encoding="utf-8"))
            if "/busybox:" in b]
    assert base, f"{image_file}: no busybox base"
    assert _load(ROOT / "deploy" / part / script).BUSYBOX == base[0]


def test_fleet_page_takes_the_core_installers_busybox():
    assert "from install import BUSYBOX" in (ROOT / "deploy" / "core" / "fleet_page.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("part", sorted(INSTALLERS))
def test_installer_refuses_a_tag_only_base(part, tmp_path):
    pinned_busybox = _load(ROOT / "deploy" / part / INSTALLERS[part][0]).pinned_busybox
    tagged = tmp_path / "Dockerfile.test"
    tagged.write_text("FROM docker.io/library/busybox:1.37.0 AS prep\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        pinned_busybox(tagged)

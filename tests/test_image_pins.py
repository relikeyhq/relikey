# SPDX-License-Identifier: EUPL-1.2
"""The image files pin every base image by digest, and Dependabot watches the directories they sit in. The files are
named Dockerfile.* because Dependabot's docker ecosystem only reads that name."""
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

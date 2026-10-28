# SPDX-License-Identifier: EUPL-1.2
"""Repository metadata: links to this repository name its real owner, and the issue forms are well formed.

The issue chooser's private-report link named another owner ("relikey" instead of "relikeyhq") from the
first public commit until 0.1.2: a reporter following it would not reach the maintainer.
"""
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
OWNER = "relikeyhq"
REPO_URL = re.compile(r"github\.com/([\w.-]+)/relikey(?![\w.-])")
FORMS = sorted((ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))


def tracked_text_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    for name in out:
        p = ROOT / name
        if p.suffix in {".md", ".yml", ".yaml", ".py", ".go", ".toml", ".txt", ".html"} and p.is_file():
            yield name, p.read_text(encoding="utf-8", errors="replace")


def test_links_to_this_repository_name_its_owner():
    wrong = [f"{name}: github.com/{m[1]}/relikey" for name, text in tracked_text_files()
             for m in REPO_URL.finditer(text) if m[1] != OWNER]
    assert wrong == [], wrong


def test_the_private_report_link_reaches_this_repository():
    config = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8"))
    assert config["blank_issues_enabled"] is False
    urls = [c["url"] for c in config["contact_links"]]
    assert f"https://github.com/{OWNER}/relikey/security/advisories/new" in urls


@pytest.mark.parametrize("form", [f for f in FORMS if f.name != "config.yml"], ids=lambda p: p.name)
def test_issue_forms_are_well_formed(form):
    data = yaml.safe_load(form.read_text(encoding="utf-8"))
    assert data["name"] and data["description"] and data["body"]
    ids = [item["id"] for item in data["body"] if item["type"] != "markdown"]
    assert len(ids) == len(set(ids)), "ids must be unique within a form"
    assert any(item.get("validations", {}).get("required") for item in data["body"]), "at least one required field"

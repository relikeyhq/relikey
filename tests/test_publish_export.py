# SPDX-License-Identifier: EUPL-1.2
"""The curated export classifies every tracked file and fails closed on a new one."""
import yaml

import tools.publish_export as pe


def _lists():
    m = yaml.safe_load(pe.MANIFEST.read_text(encoding="utf-8"))
    return m["public"], m["holdback"]


def test_known_paths_are_classified_as_intended():
    public, holdback = _lists()

    def c(path):
        return pe.classify(path, public, holdback)

    # public: the design of record and the buildable parts
    assert c("model/components.yaml") == "public"
    assert c("agent/cmd/relikey-agent/main.go") == "public"
    assert c("deploy/core/install.py") == "public"
    assert c("docs/architecture.md") == "public"
    assert c("README.md") == "public"

    # holdback wins over public on overlap, and the private trees stay private
    assert c("docs/reviews/2026-10-23-red-team-1.md") == "holdback"
    assert c("lab/lab_exposure_scan.py") == "holdback"
    assert c("deploy/secrets/edge.key") == "holdback"
    assert c(".gitlab/merge_request_templates/Default.md") == "holdback"


def test_an_unclassified_file_fails_closed():
    public, holdback = _lists()
    assert pe.classify("some/new/thing.md", public, holdback) == "unclassified"


def test_every_tracked_file_is_classified():
    """The whole current tree must be either public or holdback - never unclassified."""
    public, holdback = _lists()
    unclassified = [
        f for f in pe.tracked_files()
        if pe.classify(f, public, holdback) == "unclassified"
    ]
    assert unclassified == [], f"unclassified tracked files: {unclassified}"


def test_lab_paths_in_staged_markdown_are_neutralised(tmp_path):
    """The lab harness is held back: a mention of a path under lab/ keeps its sense and loses the dead path."""
    (tmp_path / "docs").mkdir()
    f = tmp_path / "docs" / "x.md"
    f.write_text("Proven by `lab/e2e/fs_run.sh` and lab/warpgate-keycloak/; not by deploy/edge/compose.lab.yaml.\n",
                 encoding="utf-8")
    n = pe.neutralise_holdback_links(tmp_path, "docs/x.md", ["lab/"])
    text = f.read_text(encoding="utf-8")
    assert n == 2 and "lab/" not in text.replace("compose.lab.yaml", "")
    assert text.count("the lab harness (kept with the maintainer)") == 2 and "compose.lab.yaml" in text

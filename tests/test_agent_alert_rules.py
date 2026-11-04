# SPDX-License-Identifier: EUPL-1.2
"""The edge's alerting rules (deploy/edge/relikey-agent.rules.yaml) read only the agent's stable metric names, carry a
severity and say why and what next, and every rule has a promtool unit test that makes it fire. promtool itself runs
when it is on the PATH (the rules file's header has the commands)."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "deploy" / "edge"
RULES = EDGE / "relikey-agent.rules.yaml"
TESTS = EDGE / "relikey-agent.rules.test.yaml"


def rules():
    doc = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    return [r for g in doc["groups"] for r in g["rules"]]


def stable_names():
    """The metric names docs/agent.md's Metrics table lists: the ones a release changes only with a changelog line."""
    text = (ROOT / "docs" / "agent.md").read_text(encoding="utf-8")
    table = text[text.index("| Metric | Type | Meaning |"):]
    table = table[:table.index("\n\n")]
    return set(re.findall(r"^\| `(relikey_agent_\w+)` \|", table, re.M))


def test_the_rules_read_only_stable_metrics():
    stable = stable_names()
    assert len(stable) >= 8
    for rule in rules():
        used = set(re.findall(r"relikey_agent_\w+", rule["expr"]))
        assert used, f"{rule['alert']}: reads no agent metric"
        assert used <= stable, f"{rule['alert']}: {sorted(used - stable)} may change in any release"


def test_each_rule_has_a_severity_and_says_why_and_what_next():
    for rule in rules():
        assert rule["labels"]["severity"] in {"critical", "warning"}, rule["alert"]
        assert rule["annotations"]["summary"].strip(), rule["alert"]
        assert len(rule["annotations"]["description"]) > 80, f"{rule['alert']}: say why and what to do next"


def test_the_contracts_site_rules_are_there():
    """The alert-event contract names two rules at the site: a refused bundle and a failed Warpgate action."""
    exprs = " ".join(r["expr"] for r in rules())
    assert "relikey_agent_bundles_refused_total" in exprs
    assert "relikey_agent_action_failures_total" in exprs


def test_every_rule_has_a_unit_test_that_fires_it():
    doc = yaml.safe_load(TESTS.read_text(encoding="utf-8"))
    assert doc["rule_files"] == [RULES.name]
    fired = {t["alertname"] for case in doc["tests"] for t in case["alert_rule_test"] if t.get("exp_alerts")}
    assert {r["alert"] for r in rules()} <= fired


def test_the_agent_docs_point_to_the_rules():
    assert "deploy/edge/relikey-agent.rules.yaml" in (ROOT / "docs" / "agent.md").read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("promtool") is None, reason="promtool is not on the PATH")
@pytest.mark.parametrize("args", [["check", "rules", RULES.name], ["test", "rules", TESTS.name]], ids=["check", "test"])
def test_promtool(args):
    run = subprocess.run(["promtool", *args], cwd=EDGE, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr

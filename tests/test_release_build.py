# SPDX-License-Identifier: EUPL-1.2
"""The release build accepts the tag release.yml runs on (v0.1.0 failed: the workflow ran on v*, build.py wanted
agent-v*), smoke-tests what it built and gives each binary a deterministic SBOM; release.yml gates, attests and
publishes them."""
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("agent_build", ROOT / "agent" / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "tag.gpgSign=false",
                    "-c", "commit.gpgSign=false", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "one")
    return tmp_path


def _workflow_tag_patterns():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    m = re.search(r"tags:\s*\[([^\]]*)\]", text)
    return [p.strip().strip("\"'") for p in m.group(1).split(",")]


@pytest.mark.parametrize("tag", ["v0.1.0", "v1.2.3", "agent-v0.0.9"])
def test_a_release_tag_on_head_is_found(repo, tag):
    _git(repo, "tag", "-a", tag, "-m", tag)
    assert build.release_tag(repo) == tag


@pytest.mark.parametrize("tag", ["nightly", "vnext", "release-1"])
def test_other_tags_are_not_releases(repo, tag):
    _git(repo, "tag", "-a", tag, "-m", tag)
    assert build.release_tag(repo) == ""


def test_the_tag_the_workflow_runs_on_is_one_build_accepts(repo):
    patterns = _workflow_tag_patterns()
    assert patterns == ["v*"], "release.yml's tag filter changed: check release_tag() still accepts it"
    _git(repo, "tag", "-a", "v0.1.0", "-m", "v0.1.0")
    assert build.release_tag(repo) == "v0.1.0"


# The smoke test (build.py smoke): what it refuses, on a dist/ of stand-in files.

REV = "0123456789abcdef0123456789abcdef01234567"
NAMES = ["relikey-agent-linux-amd64", "relikey-agent-linux-arm64", "relikey-agent-linux-armv7",
         "relikey-fleet-linux-amd64", "relikey-fleet-linux-arm64"]


def _elf(arch):
    cls, machine = build.ELF_MACHINE[arch]
    return b"\x7fELF" + bytes([cls, 1, 1, 0]) + bytes(8) + (2).to_bytes(2, "little") + machine.to_bytes(2, "little")


def _sbom(version, sha):
    return {"bomFormat": "CycloneDX", "metadata": {"component": {"version": version},
            "properties": [{"name": "cdx:gomod:binary:hash:SHA-256", "value": sha}]}}


def _dist(tmp_path, version="v0.2.0", arch_of=None):
    sums = []
    for name, _, arch, *_ in build.binaries():
        data = _elf((arch_of or {}).get(name, arch)) + name.encode()
        (tmp_path / name).write_bytes(data)
        bom = (tmp_path / f"{name}.cdx.json")
        bom.write_text(json.dumps(_sbom(version, hashlib.sha256(data).hexdigest())), encoding="utf-8")
        for f in (tmp_path / name, bom):
            sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
    (tmp_path / "SHA256SUMS").write_text("\n".join(sorted(sums)) + "\n", encoding="utf-8")
    return tmp_path


def _runs(version="v0.2.0", rev=REV, rc=0):
    def run(path, module):
        return rc, f"relikey-{module} {version} {rev[:12]} go1.27.3\n"
    return run


def test_the_release_binaries_are_the_ones_release_yml_attests():
    assert [b[0] for b in build.binaries()] == NAMES
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "release-build.yml").read_text(encoding="utf-8"))["jobs"]
    assert jobs["sbom-attest"]["strategy"]["matrix"]["binary"] == NAMES


def test_a_good_dist_passes_the_smoke_test(tmp_path):
    assert build.smoke_problems(_dist(tmp_path), "v0.2.0", REV, "amd64", _runs()) == []


def test_a_binary_that_does_not_run_fails_the_smoke_test(tmp_path):
    problems = build.smoke_problems(_dist(tmp_path), "v0.2.0", REV, "amd64", _runs(rc=2))
    assert [p.split(":")[0] for p in problems] == ["relikey-agent-linux-amd64", "relikey-fleet-linux-amd64"]
    assert all("does not run" in p for p in problems)


@pytest.mark.parametrize("version, rev", [("v0.1.2", REV), ("v0.2.0", "f" * 40), ("dev", REV)])
def test_a_binary_reporting_another_version_or_commit_fails(tmp_path, version, rev):
    problems = build.smoke_problems(_dist(tmp_path), "v0.2.0", REV, "amd64", _runs(version, rev))
    assert len(problems) == 2 and all("reports" in p for p in problems)


def test_a_modified_tree_fails_the_version_check():
    assert build.version_problem(f"relikey-agent v0.2.0 {REV[:12]}+dirty go1.27.3", "relikey-agent", "v0.2.0", REV)
    assert not build.version_problem(f"relikey-agent v0.2.0 {REV[:12]} go1.27.3\n", "relikey-agent", "v0.2.0", REV)


def test_a_binary_for_another_arch_fails_even_if_it_is_not_run(tmp_path):
    dist = _dist(tmp_path, arch_of={"relikey-agent-linux-armv7": "arm64"})
    problems = build.smoke_problems(dist, "v0.2.0", REV, "amd64", _runs())
    assert problems == ["relikey-agent-linux-armv7: not an ELF binary for arm"]


def test_a_host_that_runs_nothing_fails_the_smoke_test(tmp_path):
    problems = build.smoke_problems(_dist(tmp_path), "v0.2.0", REV, None, _runs())
    assert problems == ["no binary ran: the smoke test needs a linux/amd64 or linux/arm64 host"]


def test_an_sbom_of_other_bytes_or_another_version_fails(tmp_path):
    dist = _dist(tmp_path)
    (dist / "relikey-fleet-linux-arm64").write_bytes(_elf("arm64") + b"rebuilt")
    problems = build.smoke_problems(dist, "v0.2.0", REV, "amd64", _runs())
    assert any("not as SHA256SUMS lists it" in p for p in problems)
    assert any("SBOM describes other bytes" in p for p in problems)
    assert build.sbom_problem(_sbom("v0.1.2", "a" * 64), "v0.2.0", "a" * 64)


def test_a_missing_sbom_fails(tmp_path):
    dist = _dist(tmp_path)
    (dist / "relikey-agent-linux-arm64.cdx.json").unlink()
    problems = build.smoke_problems(dist, "v0.2.0", REV, "amd64", _runs())
    assert problems == ["relikey-agent-linux-arm64: binary or SBOM missing"]


@pytest.mark.parametrize("head", [b"MZ\x90\x00" + bytes(60), b"\x7fELF\x02\x02" + bytes(58), b"\x7fELF"])
def test_only_little_endian_elf_is_read(head):
    assert build.elf_target(head) is None


# The SBOM: deterministic bytes from the binary's module data.

def test_the_sbom_drops_what_differs_between_hosts_and_runs():
    bom = {"bomFormat": "CycloneDX", "serialNumber": "urn:uuid:1", "metadata": {"timestamp": "2026-10-28T00:00:00Z",
           "tools": [{"name": "cyclonedx-gomod", "version": "v1.12.0", "hashes": [{"alg": "SHA-256", "content": "x"}]}],
           "component": {"name": "relikey/agent", "version": "v0.2.0", "description": "caf" + chr(233)}}}
    out = build.normalise_sbom(json.loads(json.dumps(bom)))
    assert out.endswith("}\n") and out.isascii()
    got = json.loads(out)
    assert "serialNumber" not in got and "timestamp" not in got["metadata"]
    assert got["metadata"]["tools"] == [{"name": "cyclonedx-gomod", "version": "v1.12.0"}]
    assert build.normalise_sbom(json.loads(json.dumps(bom))) == out


def test_the_sbom_tool_is_pinned_in_its_own_module():
    mod = (ROOT / "agent" / "tools" / "sbom" / "go.mod").read_text(encoding="utf-8")
    assert re.search(r"^tool " + re.escape(build.SBOM_TOOL) + "$", mod, re.M)
    assert re.search(r"^\s+github\.com/CycloneDX/cyclonedx-gomod v\d+\.\d+\.\d+ ", mod, re.M)
    assert build.SBOM_TOOL not in (ROOT / "agent" / "tools" / "go.mod").read_text(encoding="utf-8")
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    gomod = [u for u in cfg["updates"] if u["package-ecosystem"] == "gomod"]
    assert any("/agent/tools/sbom" in u.get("directories", []) for u in gomod)


# release.yml: the gate, then the build in the reusable release-build.yml (SLSA Build L3, #28), then the release;
# the smoke test, the attestations, the keyless signatures, and the workflow hygiene.

WORKFLOWS = ROOT / ".github" / "workflows"


def _jobs(name):
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))["jobs"]


def _release_jobs():
    return _jobs("release.yml")


def _build_jobs():
    return _jobs("release-build.yml")


def _runs_of(job):
    return [s.get("run", "") for s in job["steps"]]


def test_nothing_is_built_before_ci_passed_on_the_tagged_commit():
    jobs = _release_jobs()
    assert any("tools/release_gate.py" in r for r in _runs_of(jobs["ci-passed"]))
    assert jobs["ci-passed"]["permissions"] == {"contents": "read", "actions": "read"}
    assert jobs["build"]["needs"] == "ci-passed"
    assert jobs["github-release"]["needs"] == "build"


def test_the_build_runs_in_the_reusable_workflow():
    jobs = _release_jobs()
    assert jobs["build"]["uses"] == "./.github/workflows/release-build.yml"
    assert set(jobs) == {"ci-passed", "build", "github-release"}   # nothing is built or signed in the caller
    for job in jobs.values():
        assert not any("attest" in s.get("uses", "") or "cosign" in s.get("uses", "") for s in job.get("steps", []))
    called = yaml.safe_load((WORKFLOWS / "release-build.yml").read_text(encoding="utf-8"))
    assert list(called[True]) == ["workflow_call"]   # PyYAML reads the key `on` as True
    assert set(_build_jobs()) == {"build", "sbom-attest", "images"}


def test_the_built_binaries_are_smoke_tested_before_anything_is_attested_or_signed():
    steps = _build_jobs()["build"]["steps"]
    runs = [s.get("run", "") for s in steps]
    release, smoke = runs.index("python agent/build.py release"), runs.index("python agent/build.py smoke")
    first = next(i for i, s in enumerate(steps) if "attest" in s.get("uses", "") or "cosign" in s.get("uses", ""))
    assert release < smoke < first


def test_the_sums_and_each_binary_get_a_keyless_signature_before_upload():
    steps = _build_jobs()["build"]["steps"]
    sign = next(i for i, s in enumerate(steps) if "cosign sign-blob" in s.get("run", ""))
    upload = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert sign < upload
    run = steps[sign]["run"]
    assert "SHA256SUMS" in run and "--bundle" in run and "--yes" in run
    assert _build_jobs()["build"]["permissions"]["id-token"] == "write"


def test_each_sbom_is_attested_against_its_binary():
    job = _build_jobs()["sbom-attest"]
    attest = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/attest@"))
    assert attest["with"] == {"subject-path": "dist/${{ matrix.binary }}",
                              "sbom-path": "dist/${{ matrix.binary }}.cdx.json"}
    assert job["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}


def test_the_caller_grants_the_build_what_its_jobs_need():
    granted = _release_jobs()["build"]["permissions"]
    for name, job in _build_jobs().items():
        for scope, level in job["permissions"].items():
            assert granted.get(scope) in (level, "write"), (name, scope)


def test_every_release_job_has_a_timeout_and_pinned_actions():
    for wf, jobs in (("release.yml", _release_jobs()), ("release-build.yml", _build_jobs())):
        for name, job in jobs.items():
            assert "permissions" in job, (wf, name)
            if "uses" not in job:   # a job that calls a reusable workflow cannot set a timeout; its jobs do
                assert isinstance(job.get("timeout-minutes"), int), (wf, name)
        text = (WORKFLOWS / wf).read_text(encoding="utf-8")
        for line in re.findall(r"uses:\s*(\S+.*)", text):
            if line.startswith("./"):
                continue
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}\s+# v\d+\.\d+\.\d+", line), line


# The VEX (build.py vex, #30): govulncheck's openvex output per binary, merged into one document whose products are
# the binaries as their SBOMs name them. The fixtures are govulncheck v1.9.0 output recorded on a throwaway module
# that requires golang.org/x/text v0.3.7 (one vulnerability called, two not), and on the agent module (none known).

DATA = ROOT / "tests" / "data"
TS = "2026-11-03T12:00:00Z"


def _report(name="govulncheck-openvex.json", status=None):
    doc = json.loads((DATA / name).read_text(encoding="utf-8"))
    if status:
        doc["statements"] = [s for s in doc["statements"] if s["status"] == status]
    return doc


def _purl(name, version="v0.3.0"):
    module = "agent" if "-agent-" in name else "fleet"
    arch = name.rsplit("-", 1)[1].removesuffix("v7")
    return f"pkg:golang/relikey/{module}@{version}?goarch={arch}&goos=linux&type=module#cmd/relikey-{module}"


def _products():
    return {n: build.vex_product({"metadata": {"component": {"purl": _purl(n)}}}, hashlib.sha256(n.encode()).hexdigest())
            for n in NAMES}


def _vex(reports, products=None):
    return build.vex_document("v0.3.0", TS, products or _products(), reports, "govulncheck v1.9.0 (golang.org/x/vuln)")


def test_a_product_is_the_binary_as_its_sbom_names_it():
    bom = {"metadata": {"component": {"name": "relikey/agent", "version": "v0.3.0", "purl": _purl(NAMES[0]),
                                      "bom-ref": "pkg:golang/relikey/agent@v0.3.0?type=module#cmd/relikey-agent"}}}
    assert build.vex_product(bom, "a" * 64) == {"@id": _purl(NAMES[0]), "identifiers": {"purl": _purl(NAMES[0])},
                                                "hashes": {"sha-256": "a" * 64}}
    # the purl carries the target, so the three agent binaries are three products, not one
    assert len({p["@id"] for p in _products().values()}) == len(NAMES)


def test_one_verdict_in_several_binaries_is_one_statement_listing_them():
    doc = _vex({n: _report(status="not_affected") for n in NAMES})
    assert [s["vulnerability"]["name"] for s in doc["statements"]] == ["GO-2022-1059", "GO-2026-6629"]
    for st in doc["statements"]:
        assert st["status"] == "not_affected" and st["justification"].startswith("vulnerable_code_")
        assert st["impact_statement"]   # govulncheck's own words stay
        assert [p["@id"] for p in st["products"]] == sorted(_purl(n) for n in NAMES)
        assert all(p["subcomponents"] == [{"@id": "pkg:golang/golang.org%2Fx%2Ftext@v0.3.7"}] for p in st["products"])
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0" and doc["version"] == 1 and doc["timestamp"] == TS
    assert doc["@id"] == "https://github.com/relikeyhq/relikey/releases/download/v0.3.0/relikey.openvex.json"


def test_different_verdicts_per_binary_stay_apart():
    reports = {n: _report(status="not_affected") for n in NAMES}
    reports[NAMES[0]] = _report()   # this binary calls GO-2026-5970's code
    doc = _vex(reports)
    affected = [s for s in doc["statements"] if s["status"] == "affected"]
    assert len(affected) == 1 and [p["@id"] for p in affected[0]["products"]] == [_purl(NAMES[0])]
    assert "justification" not in affected[0]


def test_the_vex_bytes_do_not_depend_on_report_order():
    reports = {n: _report(status="not_affected") for n in NAMES}
    shuffled = {}
    for n in reversed(NAMES):
        r = _report(status="not_affected")
        r["statements"].reverse()
        shuffled[n] = r
    assert json.dumps(_vex(reports)) == json.dumps(_vex(shuffled))


def test_an_affected_statement_refuses_the_vex_and_says_what_to_do():
    problem = build.vex_refusal(_vex({n: _report() for n in NAMES}))
    assert "GO-2026-5970 (CVE-2026-56852): affected in " + _purl(NAMES[0]) in problem
    assert "GO-2022-1059" not in problem   # not_affected is not a reason to stop
    assert "Next:" in problem and "build.py vuln" in problem and "tag the next version" in problem


def test_an_unknown_status_is_refused_too():
    report = _report(status="not_affected")
    report["statements"][0]["status"] = "under_investigation"
    assert "under_investigation" in build.vex_refusal(_vex({NAMES[0]: report}))


def test_a_vex_with_no_statements_is_valid():
    doc = _vex({n: _report("govulncheck-openvex-empty.json") for n in NAMES})
    assert doc["statements"] == [] and build.vex_refusal(doc) == ""


def test_the_vex_is_added_to_the_sums_in_the_release_format():
    sums = f"{'b' * 64}  relikey-agent-linux-amd64\n{'c' * 64}  relikey-fleet-linux-amd64\n"
    out = build.sums_with(sums, build.VEX_FILE, "a" * 64)
    assert out == (f"{'b' * 64}  relikey-agent-linux-amd64\n{'c' * 64}  relikey-fleet-linux-amd64\n"
                   f"{'a' * 64}  relikey.openvex.json\n")
    assert build.sums_with(out, build.VEX_FILE, "d" * 64).count("relikey.openvex.json") == 1   # a rerun replaces it


def test_the_vex_is_written_after_the_smoke_test_and_before_anything_is_attested_or_signed():
    steps = _build_jobs()["build"]["steps"]
    runs = [s.get("run", "") for s in steps]
    smoke, vex = runs.index("python agent/build.py smoke"), runs.index("python agent/build.py vex")
    first = next(i for i, s in enumerate(steps) if "attest" in s.get("uses", "") or "cosign" in s.get("uses", ""))
    assert smoke < vex < first
    attest = next(s for s in steps if s.get("uses", "").startswith("actions/attest-build-provenance@"))
    assert attest["with"]["subject-checksums"] == "agent/dist/SHA256SUMS"   # the VEX's line is in it


def test_the_vex_is_signed_with_the_binaries_and_named_in_the_notes():
    steps = _build_jobs()["build"]["steps"]
    sign = next(s["run"] for s in steps if "cosign sign-blob" in s.get("run", ""))
    excluded = re.search(r"grep -v '([^']+)'", sign).group(1)
    assert not re.search(excluded, build.VEX_FILE) and re.search(excluded, "relikey-agent-linux-amd64.cdx.json")
    notes = next(s["run"] for s in steps if "notes/notes.md" in s.get("run", ""))
    assert build.VEX_FILE in notes

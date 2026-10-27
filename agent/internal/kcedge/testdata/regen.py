"""Regenerate every reference vector file from a KeyClerk tag.

    python regen.py <keyclerk checkout> <tag>          e.g. python regen.py ../../../../../keyclerk v0.19.0

Checks the tag out into a temporary worktree (the checkout itself is untouched), copies tests/conformance/edge.json
unchanged (since KeyClerk 0.22.0 it holds the verifier cases ReliKey contributed, KC-7), runs gen_canon.py and
gen_requests.py there with KeyClerk on PYTHONPATH, and records the
tag and commit in SOURCE. Commit the result together with the pin change (model/components.yaml, clerk version).
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GENERATORS = {"canon.json": "gen_canon.py", "requests.json": "gen_requests.py"}


def main(repo: str, tag: str) -> int:
    repo_path = Path(repo).resolve()
    commit = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "--short", f"{tag}^{{commit}}"],
                            check=True, capture_output=True, text=True).stdout.strip()
    tmp = Path(tempfile.mkdtemp(prefix="kc-vectors-"))
    wt = tmp / "kc"
    subprocess.run(["git", "-C", str(repo_path), "worktree", "add", "-q", "--detach", str(wt), tag], check=True)
    try:
        shutil.copyfile(wt / "tests" / "conformance" / "edge.json", HERE / "edge.json")
        for out, gen in GENERATORS.items():
            r = subprocess.run([sys.executable, str(HERE / gen)], cwd=wt, capture_output=True, text=True,
                               env={**os.environ, "PYTHONPATH": str(wt)})
            if r.returncode != 0:
                print(f"{gen} failed:\n{r.stderr}", file=sys.stderr)
                return 1
            (HERE / out).write_text(r.stdout.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        (HERE / "SOURCE").write_text(f"KeyClerk {tag} ({commit})\n", encoding="utf-8", newline="\n")
    finally:
        subprocess.run(["git", "-C", str(repo_path), "worktree", "remove", "--force", str(wt)], check=False)
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"vectors regenerated from KeyClerk {tag} ({commit})")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]) if len(sys.argv) == 3 else (print(__doc__) or 2))

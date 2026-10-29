# Maintaining ReliKey

How work moves through this repository, from an idea to a release: the issue, the pull request, the checks it must
pass, and what the maintainer does at each step. What may be published, and how releases are signed, is in
[publishing.md](publishing.md); this page is the day-to-day process around it.

## Issues and planning
- **One shape for every issue:** What, Why, Done when, References. "Done when" is the acceptance test the pull request
  is reviewed against: checkable items, each with the test or measurement that shows it. The issue forms in
  `.github/ISSUE_TEMPLATE/` ask for exactly that.
- **A milestone per version**, plus `deferred` for what is wanted but not scheduled. Each issue sits in one milestone.
  Several projects in the same space plan this way: Pomerium (a milestone per minor version), HashiCorp Boundary (per
  version plus a deferred bucket), SPIRE (a ROADMAP.md in the repository).
- **[ROADMAP.md](../ROADMAP.md)** gives the order of work: done, next (the coming milestone, in the order it will be
  worked), then, later. Every line links its issue. It changes in the same pull request that adds or moves an issue.
- **Labels** say where the change lands (`agent`, `fleet`, `model`, `ci`, `release`, `supply-chain`, `compliance`,
  `demo`, `documentation`) and what it is (`bug`, `enhancement`).
- A security weakness never becomes a public issue: it goes through a private advisory (`SECURITY.md`).

## Pull requests
- **One issue, one branch, one pull request**, closing its issue with `Closes #N` in the description and the commit.
  Two issues share a pull request only when they edit the same lines (a release workflow change, for example).
- **The template** asks what and why, the decision records and model files touched, the changelog fragment, and the
  AI-use level. Commits carry an `Assisted-by:` trailer when an AI assistant wrote part of them (CONTRIBUTING.md).
- **Changelog fragments, never CHANGELOG.md.** A pull request adds `changelog.d/<issue>.<section>.md`
  (`changelog.d/README.md`). Editing the one `[Unreleased]` list made every open pull request
  conflict with the next merge; separate files never conflict.
- **Every new file is classified** in `tools/publish-manifest.yaml` (public or held back); the tests fail on an
  unclassified file, because the export fails closed.
- **Wording.** Every pull request, issue, comment and discussion is checked by the public text workflow; a hit labels
  it `held-for-text-review` for the maintainer. Run `python tools/public_text_check.py --text FILE` on a body before
  posting it, and `--range origin/main..HEAD` on the commits.

## The checks a pull request must pass
`main` is protected by a ruleset: a pull request is required (no approvals needed while there is one maintainer),
squash is the only merge method, review threads must be resolved, force pushes and deletion are blocked, and these
status checks must pass on a branch that is up to date with `main`:

| Check | What it runs |
|---|---|
| Model, conformance, tests | `tools/check_model.py`, the conformance set and `python -m pytest` |
| Edge agent gate | `agent/build.py check`: toolchain, gofmt, vet on four targets, staticcheck, tests, mutants |
| Export leak gate | `tools/publish_export.py --strict`: every file classified, no private pattern, gitleaks |
| Licensing (REUSE) and lint (ruff) | `reuse lint`, `ruff check .` |
| Fuzz the Python tools (Hypothesis) | property tests of the parsers and checkers |
| Analyze (actions, go, python) | CodeQL |

A pull request runs only the mutants it can affect (`agent/mutants.py --changed`); `main`, a nightly schedule and a
manual run take the full set in parallel shards. "Up to date" means a branch behind `main` is updated before it merges
(the "Update branch" button merges `main` into it); with fragments that update never conflicts.

## Merging
The maintainer merges, one pull request at a time, after its checks are green. Order matters only where one change
needs another: a change that speeds up CI or removes a conflict source goes first. After each merge the next pull
request is updated and its checks run again. Branches are deleted on merge.

## Releases
In short ([publishing.md](publishing.md) has the detail): a release pull request runs
`python tools/changelog.py release X.Y.Z`, which folds the fragments into `## [X.Y.Z]`; after it merges, the
maintainer signs the tag `vX.Y.Z` on that merge commit by its full hash with the release key, in their own terminal;
`release.yml` builds reproducibly, attests provenance and publishes the release with that section as its notes. A tag
is never moved: a failed release is fixed in the next version.

## Dependencies
Dependabot proposes updates weekly for the GitHub Actions (pinned by commit hash), Go modules, the hash-locked Python
requirements and the image bases (pinned by digest). Each update is an ordinary pull request through the same checks.

# Publishing and contributing in the open

From v0.1.0 the public repository, github.com/relikeyhq/relikey, is the engine's source of record (decision 0027).
Every engine change lands there as an issue and a pull request, merged by a maintainer after CI. A private companion
repository keeps what is not engine (review records, the lab, deployment secrets, private configuration) and pins the
engine by release tag; it never carries engine code.

## Everything posted is public at once
Diffs, commit messages, issue text, pull request bodies and comments are public the moment they are pushed or posted,
and cannot be withdrawn. `tools/public_text_check.py` scans that text: identity and local paths are hard failures,
attack detail and infrastructure are flags a human reads. It runs in three places:

- **The pre-push hook** (`hooks/pre-push`, installed with `git config core.hooksPath hooks`) checks each range pushed to
  a github.com remote: added lines, commit messages and gitleaks. A hard failure stops the push. Flags stop it too
  until read: run the check with `--flags-ok` on that range, then push with `RELIKEY_FLAGS_READ=1`.
- **By hand, before posting:** `python tools/public_text_check.py --text body.md` for every issue, pull request or
  comment text a maintainer writes.
- **The Public text workflow** (`.github/workflows/public-text.yml`) checks every pull request, issue, discussion,
  review and comment, outside contributions included. It runs the base branch's check on the text and on the pull
  request's commits fetched as data; the proposed code is never checked out or run. A hit labels the item
  `held-for-text-review` for a maintainer; the maintainer removes the label once the text is fine or changed.

The repository's wiki stays off: wiki edits skip pull requests and this workflow. Documentation lives in `docs/`, where
every change passes all three checks.

Patterns that would publish what they guard live outside the public repository: in the companion's
`tools/publish-private.yaml` for local runs and in the `RELIKEY_PRIVATE_PATTERNS` secret for the workflow (one regex per
line). Reports name such a pattern by number only.

## How a public change is worded
A change states what it changes, the threat it guards against at design level, and its tests. It may name a review
finding by its identifier (AG-n, RT-n, E-n, A-n, "full-stack run n"); the review itself stays with the maintainer, and
each code comment states the threat and the guard itself.

## Releases
A release is a signed tag `vX.Y.Z` on `main`, signed with ReliKey's own release key (its public half,
`relikey.allowed_signers`, is in the repository root; `tools/release_key.py create` makes the key, keeps it and its
passphrase in Bitwarden and writes that file). The tag needs a `## [X.Y.Z]` section in CHANGELOG.md;
`release.yml` builds the agent and the fleet service reproducibly, attests their provenance and publishes the GitHub
release with that section as its notes.

Tag the merge commit by its full hash, after the change it needs has merged, not `origin/main` from a clone that may
be behind. Release tags are never moved or deleted (a ruleset enforces it): a tag whose release build fails stays,
and the next version number carries the fix, as 0.1.0 and 0.1.1 did.

## How main stays signed
Every commit on `main` is a squash merge that GitHub makes and signs: the `main` ruleset requires a pull request and
allows squash only, and blocks force pushes and deletion. The ruleset does not also require signed commits, because
that rule checks every commit on a pull request's branch and would refuse unsigned contributions that are squashed
anyway. So the guarantee rests on squash-only merging: turning merge commits or rebase merging back on (in the
ruleset or in the repository's merge settings) would let unsigned commits reach `main`, and needs the signed-commits
rule back first. The `release tags` ruleset keeps it: a `v*` tag must point at a signed commit.

## The bridge to v0.1.0: the curated export
Before v0.1.0 ReliKey was built in the private repository. The first public release is cut from it by
`python tools/publish_export.py --strict --snapshot v0.1.0`, which is fail-closed:

- Every git-tracked file is classified `public` or `holdback` from `tools/publish-manifest.yaml`; a file in neither
  fails the export. `holdback` wins over `public`, so `docs/` is public while `docs/reviews/` is not.
- Public files are staged into `build/public-export/`, scanned for identity and local paths (hard fail) and flagged
  where their prose may carry attack detail or infrastructure, and `gitleaks` runs on the staged tree.
- `--snapshot` commits the staged tree, once every check passed, to the local `publish/snapshot` branch, authored with
  the steward identity from the held-back configuration: the public history starts with this one commit.

The tool never pushes and never creates anything; pushing the snapshot and making the repository public are the
maintainer's steps. After v0.1.0 is published the export, its manifest and the snapshot branch leave the engine.

### Flagged prose, reviewed 2026-10-24
The gate flags prose a human must read before a release. Reviewed: the "red team" lines in the decision records and
docs name that a review happened, its finding identifiers (RT-, AG-, GE-) and the decision taken; 0007's context names
the weaknesses of an earlier design iteration, each fixed by that decision, at design level only; 0008 describes a
mitigation built on Warpgate's public behaviour. None is a report, a residual, a live limit or infrastructure, so they
stay. Links and paths into held-back review records are rewritten in the staged copy (the words stay, the target goes),
so the public tree has no dead links; the IP flag ignores loopback, private and documentation ranges; the deployment
names the model check refuses live in the held-back file, not in its public source.

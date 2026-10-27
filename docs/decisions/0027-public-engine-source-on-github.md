# 0027: The engine's source of record is its public repository; a private companion keeps the rest

- Status: accepted (operator, 2026-10-27)
- Date: 2026-10-27
- Changes: the curated export (docs/publishing.md) becomes the one-time bridge to the first public release, v0.1.0,
  and is retired after it.
- Builds on: 0001 (a release is its pins and its configuration)

## Context
ReliKey was built in a private repository and published by a curated export: every tracked file classified public or
held back, the public tree staged, scanned and committed as one snapshot per release. That keeps the private history
private, but it makes the public repository a mirror. A change proposed there has to be carried back by hand, review
happens where outside contributors cannot see it, and the public history says nothing about how the engine evolves.

From v0.1.0 the engine is developed in the open. What must not go public is small and stable in kind: review records,
lab tooling, deployment secrets and material that is not engine.

## Decision
1. **The public repository is the engine's source of record.** From v0.1.0, every engine change lands on its `main`
   through an issue and a pull request, merged by a maintainer after CI. Releases are signed tags there.
2. **A private companion repository keeps the rest.** It holds what is not engine: review records, the lab and its
   full-stack runs, deployment secrets, private configuration and non-engine material. It never carries engine code;
   it pins the engine by release tag (or by commit for a lab run of unreleased work), as the lab already pins KeyClerk.
3. **The leak gate moves from export time to contribution time.** Everything in the public repository is public the
   moment it is pushed, including issue text, pull request bodies, review comments and commit messages. One check,
   `tools/public_text_check.py`, scans that text with the same patterns the export used (identity and local paths as
   hard failures, attack detail and infrastructure as flags a human reads), and runs in three places:
   - a pre-push hook, on each added diff line and each commit message bound for the public repository;
   - by hand, on every issue, pull request or comment text before it is posted;
   - a workflow on pull requests, issues and comments, so outside contributions are checked too. It runs the trusted
     base revision's check, never the proposed code, on the text and the diff only; patterns that would themselves
     publish something are passed in as a secret.
4. **Reasoning that would expose stays private.** A public change states what it changes, the threat it guards against
   at design level, and its tests. It may name a review finding by its identifier; the review itself stays private.
5. **ReliKey signs its own releases** with a dedicated release key, not a person's key; its public half is published
   with the repository.

## Consequences
- No sync step and no drift: the engine exists in one place. The private repository cannot fix an engine bug in
  private; the fix goes through a public pull request, worded at design level.
- The public history starts at v0.1.0. Earlier work is summarised in the changelog.
- The export tool, its manifest and the snapshot branch remain until v0.1.0 is published, then leave the engine.
- A wrongly worded commit message cannot be withdrawn once pushed; the pre-push hook is the last point where it can
  be changed.

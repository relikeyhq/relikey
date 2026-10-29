# Contributing

- Every change keeps the gate green: `python tools/check_model.py` and `python -m pytest`; the pre-push hook runs both
  (`git config core.hooksPath hooks`).
- ReliKey forks and patches no component (decision 0001). Code that a contract needs goes into a KeyClerk plugin or
  upstream.
- ReliKey names no deployment, customer or site; the model check fails if a file does.
- How issues, pull requests, checks and releases work: [docs/maintaining.md](docs/maintaining.md).
- A change worth a line in the changelog adds a fragment, `changelog.d/<issue>.<section>.md`, instead of editing
  `CHANGELOG.md` (`changelog.d/README.md`); open pull requests then never conflict over it.
- Design decisions go in `docs/decisions/`; open questions in `model/open-decisions.yaml`; review records stay with the
  maintainer.
- AI-assisted contributions say so in an `Assisted-by:` trailer and tick the AI-use level in the pull request
  template (`.github/PULL_REQUEST_TEMPLATE.md`). The maintainer's own work is "Human-designed, AI-coded".
- ReliKey is licensed under EUPL-1.2. Outside contributions need a contributor licence agreement (the same one as
  KeyClerk's), which is being prepared; until it is published, outside contributions cannot be accepted.

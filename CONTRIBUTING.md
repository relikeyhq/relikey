# Contributing

- Every change keeps the gate green: `python tools/check_model.py` and `python -m pytest`; the pre-push hook runs both
  (`git config core.hooksPath hooks`).
- ReliKey forks and patches no component (decision 0001). Code that a contract needs goes into a KeyClerk plugin or
  upstream.
- ReliKey names no deployment, customer or site; the model check fails if a file does.
- Every failure an operator can meet (an installer's refusal, an agent or fleet error, a page's refusal) says what
  happened, why, and what completes the task, or who can: an operator at a site with no network and no developer at
  hand needs the next step in the message itself. Name the flag, field or file at fault and the value given, and point
  to the command or person that fixes it. A refusal sent to an unauthenticated peer says less on purpose; its reason
  then goes to the service's log, and the log entry carries the next step. Tests pin the next step, not only the
  refusal (`tests/test_installers.py`).
- Design decisions go in `docs/decisions/`; open questions in `model/open-decisions.yaml`; review records stay with the
  maintainer.
- AI-assisted contributions say so in an `Assisted-by:` trailer and tick the AI-use level in the pull request
  template (`.github/PULL_REQUEST_TEMPLATE.md`). The maintainer's own work is "Human-designed, AI-coded".
- ReliKey is licensed under EUPL-1.2. Outside contributions need a contributor licence agreement (the same one as
  KeyClerk's), which is being prepared; until it is published, outside contributions cannot be accepted.

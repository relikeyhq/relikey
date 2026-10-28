# Changelog fragments

A pull request records its change here instead of editing `CHANGELOG.md`, so open pull requests never conflict over
the same list. Add one file per change, named `<issue>.<section>.md`:

- `<issue>` is the issue number (or a short lowercase slug when there is none);
- `<section>` is one of `added`, `changed`, `deprecated`, `removed`, `fixed`, `security` (Keep a Changelog).

The file holds Markdown bullets in the style of `CHANGELOG.md`: each entry starts with `- `, continuation lines are
indented two spaces, lines stay within 120 columns, punctuation is plain ASCII. Example, `19.fixed.md`:

    - The agent retries a transient read from the bastion within the same tick, and still fails closed when the
      retry fails too.

`python tools/changelog.py check` checks the fragments (the test suite runs it); `show` prints the coming release
notes. Preparing a release, `release X.Y.Z` folds the fragments into `## [X.Y.Z]` and removes them
(`docs/publishing.md`).

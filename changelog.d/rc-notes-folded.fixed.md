- A release candidate tagged after the release pull request now builds: its notes come from the release's folded
  `## [X.Y.Z]` section when there is one, and from the fragments in `changelog.d/` otherwise. `v0.3.0-rc.1` stopped at
  its notes, since the fragments it looked for had been folded; the tag stays and `v0.3.0-rc.2` carries the fix.

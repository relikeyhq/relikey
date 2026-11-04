- The release steps (`release`, `smoke`, `vex`, `dist`) moved from `agent/build.py` to `agent/release.py`; the
  commands stay `python agent/build.py ...`. build.py is the mutants' harness, so a change to the release steps no
  longer runs every mutant on a pull request and again in the merge queue.

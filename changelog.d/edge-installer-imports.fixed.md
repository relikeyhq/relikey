- The edge installer checks the Python packages it needs (PyYAML, cryptography) before it writes anything, and says how
  to get them: a Python without them, such as a bare uv Python 3.13 for enrolment by code, had half-installed the edge
  and died with a traceback, leaving an edge its own rerun refused (#185). The guide gives a `uv run` command that works.

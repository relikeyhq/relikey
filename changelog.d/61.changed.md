- The model matches what ships: the edge's filtering proxy is recorded as the pinned Caddy front it was built as, and
  the LDAP facade carries the tag and digest the edge runs. C-05 names the configuration that builds it, and C-08 and
  C-09 say which part exists (the phoned-unlock code and its vectors; leaving the break-glass account alone).
- `tools/check_model.py` refuses a shipped compose file whose upstream image is not pinned by tag and digest, is named
  by no component of that tier, or differs from the component's version or digest.

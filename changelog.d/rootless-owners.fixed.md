- Rootless podman installs now finish: the core and edge installers and `fleet_page.py` set the owners their containers
  need through `podman unshare`, where they used to print a note and carry on until KeyClerk, the fleet or the agent
  could not read its files. The edge installer also makes the agent's state volume the agent's, mode 0700, before
  compose first mounts it. A re-run after the first sign-ins no longer fails on the deleted `people.json`.

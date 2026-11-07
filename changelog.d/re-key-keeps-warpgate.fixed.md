- `deploy/edge/install.py --re-key` works over an installed edge: it kept dying at Warpgate's first setup ("Config file
  already exists"), so it now keeps Warpgate's configuration and data and the facade's `lldap.env`, and changes only the
  enrolment key and admin token. Without `--re-key`, an existing Warpgate is refused before anything is written. On
  rootless podman the installer no longer crashes on the files it gave the agent (#186).

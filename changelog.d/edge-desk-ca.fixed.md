- An edge installed with `--desk-ca` (the guide's route for a local CA) now starts: the installer wrote
  `deploy/secrets/desk-ca.pem` and pointed the agent at `/etc/relikey/desk-ca.pem`, but the pod never mounted it, so
  the agent restart-looped on a missing file. An edge installed with a pin is unaffected.

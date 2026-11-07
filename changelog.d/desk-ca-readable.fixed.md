- An edge installed with `--desk-ca` on rootless podman starts: the installer writes `desk-ca.pem` 0644 (a public CA
  certificate), where it wrote it 0600 owned by the installing user and the agent could not read it (#164). A test
  checks that every file compose mounts into the agent is one it is given or one written world-readable.

- The core's desk reports healthy on rootless podman: its health check's Python had spaces, and podman 4.9's
  compose API splits the test on whitespace, so the check always failed (#179).

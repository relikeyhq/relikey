- The core's `install.py --port` now changes the port the front is published on, not only the URLs: `deploy/core/compose.yaml`
  published 443 whatever `--port` said, so on rootless podman, which cannot bind 443, the guide's advice of a higher
  port failed. An older `core.env` without `FRONT_PORT` still publishes 443.

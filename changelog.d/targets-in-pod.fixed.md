- `deploy/edge/targets.py` now applies the targets on every install, not only with `--lab`: Warpgate's admin API is
  on the pod's loopback, which the host cannot reach, so the script checks the file on the host and hands it to the
  agent's new `targets` command in the pod (`compose exec agent`), which applies it with the agent's own pinned
  certificate and token. The pod must be running; `--engine docker` for docker. Found by the v0.3.0-rc.2 walk (F14).

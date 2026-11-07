- The core's and the edge's installers now refuse a `deploy/secrets/` that holds the other's files (`agent.json`,
  `core.env`), before writing anything: both write `front.crt` and `front.key` there, and an edge installed from the
  core's checkout replaced the core's certificate, so nothing on the core's names verified any more. The install
  guide says to use one checkout per component. Found by the v0.3.0-rc.2 walk (F15).

- Prometheus alerting rules for an edge site, `deploy/edge/relikey-agent.rules.yaml`: a silent or unhealthy agent, a
  refused bundle, a failed Warpgate action, Warpgate unreadable, failing pulls and an edge the desk ended, each with
  what to check next and a promtool unit test (docs/agent.md, Alerting rules). The staleness threshold the docs
  suggested is 180 s now, three heartbeats, since 120 s could fire on a live agent between scrapes.

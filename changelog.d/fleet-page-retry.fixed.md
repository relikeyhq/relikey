- The fleet page now starts by itself once the broker answers. Before, a fleet that started before the broker (the
  core starts them together) logged that the page did not start and stayed without it until someone restarted the
  fleet. It now retries with backoff (2 seconds, doubling, up to a minute) and logs each miss with what to check.
  Found by the v0.3.0-rc.2 walk (F9).

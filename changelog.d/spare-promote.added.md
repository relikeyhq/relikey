- `relikey-agent promote -statement FILE` makes a spare the edge's active node by hand (decision 0028): it checks the
  site key's promotion statement (edge protocol 1.5, `kc-edge-site-v1`) against the new `pins.site_key`, this edge and
  this node, and the agent then reports a break-glass activation, which the desk records with its incident. The check
  is tested against KeyClerk's own reference. KeyClerk 0.29.0 moves promotions to `kc-edge-site-v2` with an expiry.

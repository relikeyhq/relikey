- A spare's promotion statement now expires (edge protocol 1.6, KeyClerk 0.29.0): `relikey-agent promote` takes
  only `kc-edge-site-v2`, whose `not_after` is after its `at` and at most a day later, and refuses one that has passed,
  judged at the later of the node's clock and the newest signed time it holds. A statement found later can no longer
  promote a node again; a 1.5 statement (`kc-edge-site-v1`) is refused as a promotion. Checked against KeyClerk's
  reference and its own `site` conformance family.

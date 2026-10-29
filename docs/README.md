# ReliKey documentation

Docs as code: these pages live beside the code, change in the same commits, and are checked on every push
(`python tools/docs.py check`, run by the tests). The reference is generated from the model and the code, never written
by hand.

## Run it (guides)
- [Install the core](../deploy/core/README.md): the shared core pod, an edge's registration at the broker, a vendor's
  own sign-in, approval proofs on an existing core
- [Installation checklist](installation-checklist.md)

## Understand it (concepts)
- [Architecture](architecture.md): the roles, the zones and the one path in
- [The edge agent](agent.md): what it applies, what it refuses, how it fails closed
- [The KeyClerk edge interface](keyclerk-edge-interface.md): bundles, ceilings, leases and visit leases on the wire
- [Decisions](decisions/README.md): why ReliKey is built the way it is

## Look it up (reference, generated)
- [Reference](reference/README.md): components and pins, contracts, flows and ports, access patterns, profiles,
  agent.json, commands

## Work on it (engineering)
- [Go engineering](go-engineering.md), [measurements](measurements.md), [component facts](component-facts.md)
- [Warpgate internals](warpgate-internals.md), [upstream work](upstream.md), [the Windows port](warpgate-windows-port.md)
- [Prior art](prior-art.md), [publishing](publishing.md), [maintaining](maintaining.md): issues, pull requests,
  checks, merging and releases

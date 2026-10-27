# 0005: A small edge next to the system, a shared core elsewhere

- Status: accepted (operator, 2026-10-23: as amended by 0007, 0008 and 0009 after red team 1)
- Date: 2026-10-23
- Amended by 0009: the edge keeps a sized recording store; Warpgate is glibc-linked (not a static binary) and about
  100 MB on disk; armv7 stays a stretch profile that only warns.
- Amended by 0007: the edge decides with policy signed in the core, inside a per-edge ceiling it cannot widen
  (point 3 below is superseded on that); hardware profiles, time and remote reach as decided there.
- Amended by 0006: the edge keeps undelivered evidence (offline sign-ins, break-glass) until the core acknowledges it.
- Operator, 2026-10-23: "it should be able to run as a container on a modern switch or on a raspberry easily so people
  don't have to put servers next to their legacy hardware appliance or old robot".

## Context
The systems ReliKey wraps are often hardware: an appliance, a machine controller, a robot. Next to them there is a switch
port, not a server room. Keycloak is a JVM service needing several hundred MB of memory; it cannot be the part that sits
next to a robot. Warpgate is a single static binary for arm64 and x86_64; glauth and lldap build for armv7, arm64 and
amd64. Enforcement is small; identity and governance are not.

## Decision
1. ReliKey has two tiers (`model/components.yaml` `tier:`):
   - **Edge**, next to the legacy system: Warpgate, the LDAP facade and the edge agent. Nothing else.
   - **Core**, once per organisation or site, on normal compute: Keycloak, KeyClerk, optionally OpenBao. One core serves
     many edges.
2. The edge must fit the profiles in `model/footprint.yaml` (a switch's container host with 512 MB for apps, a 1 GB
   single-board computer, and as a stretch a 256 MB armv7 router) using at most half of each, on every listed
   architecture. The model check enforces the sum; measurements on real hardware replace the estimates before 1.0.
3. **The edge decides nothing.** KeyClerk decides in the core and signs leases into bundles (KeyClerk 0013 D3); the agent
   verifies and applies them through Warpgate's and the facade's local APIs (C-01 to C-04). Session approvals are given
   at the edge from a signed lease, so an edge cut off from the core keeps working until the bundle's horizon, then
   ends every lease (fail closed).
4. **The edge only connects out.** Edge-to-core flows are opened by the edge (F-04, F-06, F-09); the core never needs a
   path into the switch or the board. The admin APIs of Warpgate and the facade listen on the edge's loopback only.
5. **The edge keeps no history.** Session recordings and audit events stream to the organisation's store (F-09) as they
   happen; the edge holds a scratch copy only, so a small flash disk is enough.
6. This replaces OpenBao as the LDAP rotator (old R-01 lean): the agent rotates facade passwords itself, because putting
   OpenBao on the edge would cost more than the facade and the agent together.

## Consequences
- The "small appliance" is the edge; the core is shared infrastructure a provider or the organisation runs once. A
  single-site deployment may run core and edge on one small server; the edge alone never runs Keycloak.
- New sign-ins need the core reachable (R-09); an edge that loses its uplink keeps open sessions and leases until the
  horizon, not longer.
- The edge agent is the one new piece of code ReliKey needs; R-08 decides whether it is a KeyClerk profile or a small
  static binary. Either way it holds no policy and names no deployment.
- Footprint numbers in the model are estimates until a soak on the R-10 reference hardware.

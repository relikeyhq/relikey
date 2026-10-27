# 0013: The HA witness is a profile setting: the core when connected, on site under DDIL

- Status: accepted (operator, 2026-10-24)
- Date: 2026-10-24
- Amends: 0012 HA-1 (layered HA profile)
- Operator, 2026-10-24: first "core as witness" (recommended in answer to KeyClerk's red team: two-node PostgreSQL has
  no quorum, so a split can leave both agents active); then, asked "how does this work in DDIL when cut off?", the
  operator accepted the amendment below: "yes send the HA witness correction and write".

## Context
0012 made HA optional but supported: a two-node edge (Warpgate cluster on PostgreSQL, lldap on it, a floating address,
the agent active/standby by a PostgreSQL advisory lock). Two nodes cannot tell "my peer is down" from "the link to my
peer is down", so without a third vote either both stay active (split brain in the shared database) or neither takes
over. KeyClerk's red team (2026-10-24) asked for a witness or fencing.

A witness at the core answers the connected cases, but not the one HA exists for on a site that works cut off
(0006): when the site has lost the core and the active node fails, the survivor holds one vote of three and may not
promote. The site goes down exactly when a second node should carry it.

## Decision
1. **Three votes, the witness chosen by profile.** The two nodes and one witness. The active node holds its role only
   while it holds a majority.
   - Connected profile: the witness is the core (no extra hardware).
   - DDIL profile: the witness is on site: a small third device that holds a vote and no data (an SBC, or the
     switch-sized edge where one exists). It sits on the site network, not behind the uplink.
   The profile is attested like every other (0012 R-16): configuration may choose the stronger witness, never none.
2. **What runs without quorum.** Access control never needs quorum: cut off, each node applies its own last verified
   bundle and leases only run out on their horizons (0011). Two nodes doing so independently cannot grant more than
   their bundles allow. Quorum guards the shared state only: the PostgreSQL primary, Warpgate's cluster writes and the
   agent's active role (it applies to Warpgate). A node without a majority keeps its database read-only and its agent
   passive.
3. **Break-glass promotion, last resort, any profile.** An on-site operator can promote the surviving node by hand
   with a physical key held for that site (0006 levels, 0008 H3). It is logged locally, shown on the status page, and
   reported to the core and to KeyClerk's records when the link returns; the other node, if it comes back, rejoins as
   standby and never as primary.
4. **Per node, not per pair.** Each node has its own enrolment key, bundle, serial and floors (KeyClerk statement
   nodes, 0.23.0; per-node state, 0.26.0); a node's reports say how it became active: by majority with the core, by
   majority with the local witness, or by break-glass, with when and by whom.

## Consequences
- The two-node edge with a remote witness keeps working through a core outage as long as both nodes and their link
  are up; only a node failure during a core outage needs a local witness or break-glass.
- DDIL sites need a third device. It carries no secrets and no data, so losing or stealing it costs a vote, not access.
- The agent's active/standby (0012) moves from a bare PostgreSQL advisory lock to a lock that is only valid with a
  majority; the implementation picks a proven mechanism (for example Patroni-style leader leases on a small consensus
  store) rather than writing one, and states it in the HA profile.
- KeyClerk 0.26.0 (desk side of HA) must not assume the core is always the witness: told 2026-10-24.
- Not yet built: the HA profile itself (decision 0012 HA-1 lists the layers).

## Changelog
- 2026-10-24 Created: amends 0012 HA-1 after the DDIL question.

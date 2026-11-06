# 0028: The two-node edge: nothing that grants is replicated; a third vote only for the site's address

- Status: proposed (draft 3, 2026-11-06), for the maintainer's decision between options A and B. Nothing built.
  Amends 0012 HA-1 and 0013 (the Warpgate cluster on PostgreSQL) if A is accepted.
- Date: 2026-11-06
- Builds on: 0012 HA-1, 0013 (three votes, the witness by profile, break-glass), 0003 (LDAP lease credentials), 0006
  (working without a network), 0011 (the agent), 0025 (evidence), 0026 (the fleet service); KeyClerk 0031 points 1 and
  2 and edge protocol 1.5 sections 7.3, 9, 10, 11 and 14. Issue #127.
- Reviews (2026-11-06): draft 1 modelled and reviewed adversarially; draft 2 reviewed adversarially, checked against
  the agent's, Warpgate's and KeyClerk's code, and against the code of keepalived, kube-vip, client-go's leader
  election, vip-manager and corosync-qdevice; its address arbiter modelled with messages, freezes and loss.

## Context
0012 and 0013 decided a two-node edge as a Warpgate cluster on PostgreSQL, the agent active/standby, three votes.
Draft 1 chose pg_auto_failover. Its model and review found it hard to make safe: fencing by elapsed time (the monitor
promotes after about 50 s on the belief that the old primary stopped; two writable databases came back in the model
even with a hardware watchdog), access depending on the election (a demoted node's Warpgate cannot serve), lost
writes including revocations on failover, a monitor at the core that holds every edge's database, and a break-glass
that could leave two writers.

In ReliKey the signed bundle is the authority (0011). Warpgate's users, roles and credentials are derived from it by
the agent, which compares desired with observed state in full on every tick (agent.go reconcile; checked). Replicating
Warpgate's database replicates a cache, and the election exists only to keep that cache single-writer.

## Options
| | A: two whole edges (proposed) | B: a Warpgate cluster, Patroni + etcd |
|---|---|---|
| Shared | nothing that grants; the identity clients see (host key, TLS certificate, SSO client) | Warpgate's database |
| The third vote decides | who holds the site's address | whose database is writable |
| Split brain costs | both serve from their own verified bundles; two holders of the address for seconds | two writable databases unless leader key and watchdog hold |
| Access without quorum | yes, every node (0013 point 2 as written) | no |
| Fencing for safety | none | leader key + watchdog, bare metal only |
| Kept whole | | one session history, one evidence chain, one lease credential, desk semantics as built |
| Needs | the node-scoped changes in point 6 (KeyClerk and ReliKey) | PostgreSQL, Patroni, etcd per node; no armv7 |

## Decision (proposed): A
1. **Two whole edges.** Each node is today's single-node pod with its own enrolment key, state, floors, serials, unlock
   key and Warpgate on SQLite, enrolled as one edge's two nodes. Both agents always apply and end sessions on their
   own node, whatever happens to the address or the other node. Nothing that grants access is replicated.
2. **The address arbiter.** Votes are the two nodes and the witness (the core when connected, a device on site under
   DDIL, 0013), counted as corosync-qdevice does: the two nodes together are a majority without the witness, and the
   witness only breaks a split between them.
   - Together (each hears the other's heartbeat): the holder keeps the address; when both hold, the witness's recorded
     holder keeps it (A when none is known); when none holds, the recorded holder takes it (A when none is known).
   - Apart: the address needs the witness's lease, a compare-and-swap record. A holder renews every `retry`, keeps the
     address only while `now - send_time(last accepted renew) < renew_deadline` on its own monotonic clock, and
     releases it then; a challenger takes it only after seeing the record unchanged for `lease` on its own clock. The
     install refuses settings where `retry + renew_deadline + delay >= lease` (2, 8 and 15 s by default). client-go
     checks only `renew_deadline < lease`; ours checks the sum (prior art, below).
   - A node waking from a freeze checks its deadline before anything else.
   - Without the peer and without the witness a node does not hold the address; it still serves on its own address.
   - Gratuitous ARP on taking the address. Industrial clients that ignore it are measured on the target switches
     before the profile is offered; a virtual MAC is documented with its port-security caveat.
3. **The activation report** is the address holder's: `by` from the vote that gave it the address (the witness's
   record, or the peer's agreement, reported as the profile's `witness` or `local_witness`), `at` the moment it took
   it; `break_glass` with the site key's promotion statement when an operator gave it by hand. It claims who serves
   the site's address, nothing more: both nodes enforce, and lying in it gains no access.
4. **Break-glass gives the address, not a database.** `relikey-agent promote -statement FILE` checks the site key's
   promotion statement for this edge and node and takes the address without the vote. Asked of KeyClerk: a validity
   window in the promotion statement.
5. **What clients see is shared, and said so.** One SSH host key (Warpgate imports a `host-ed25519` file at its first
   start), one TLS certificate for the site's name, and the edge's one SSO client and its secret are installed on
   both nodes. They are shared secrets: a node holding them has no more than it already has. Warpgate's own key
   towards the targets is shared the same way, or both nodes' keys go into each target account; `targets.py` runs
   against both nodes and a check compares their target sets.
6. **Node-scoped changes, before the profile is offered.**
   KeyClerk (asked, with code references from the review):
   - the ended notice names every node's key (`desk.py` builds it from the first node's only): blocking;
   - phoned unlock takes the node from the request and uses that node's unlock key (always node 1 today): blocking;
   - removals stored per node, an edge's removal proven when every node confirmed it, and a node's decommission
     (dropping `node2`) that settles its pending removals;
   - report comparisons (attestation, bastion, drift, active node) and the incident cap per node;
   - the evidence chain per node, before C-12 is built;
   - relay tightenings accepted against a node's own applied serial;
   - the escrow item id with the node in it.
   ReliKey:
   - the fleet service keyed by edge and node (it refuses a second node's key today): blocking;
   - the event source `edge/<node key id>`;
   - the activation report and the arbiter;
   - LDAP lease credentials (0003) minted once per lease and installed on both nodes, never rotated per node.
7. **Accepted residuals.** A carried visit lease (section 9) works on both nodes, and a node that never saw a newer
   carried serial accepts the older one until its window ends (at most 24 hours); nodes exchange their carried floors
   when they hear each other. Each node's session history and recordings are its own; a dead node loses what it had
   not sent to the core. Open sessions drop when the address moves.

## Model (2026-11-06)
- Access and the leaver proof (both nodes always enforcing; 3,108 single and double faults of crashes and the five
  links): no node holds a revoked role after its next successful pull. With KeyClerk's per-edge removal rule the desk
  claims a removal while a node still holds the role in 1,112 scenarios (up to 30 minutes: a node cut from the core);
  with the per-node rule in none.
- The address arbiter, with messages, loss, freezes and crashes (1,400 scenarios): two awake holders in 12 scenarios
  for at most 2 s (a heartbeat in flight); a frozen holder keeps the address configured until it wakes (its kernel
  answers for it), in 152 scenarios for as long as the freeze; no holder for at most 120 s, in double faults that
  leave no majority. The model found and fixed two rule errors on the way (two incumbents after a freeze; nobody
  taking after both crashed).

## Prior art (code read 2026-11-06)
keepalived's VRRP has no third vote: a cut between the nodes makes both masters (a ping-style `vrrp_script` only puts
a node in FAULT). kube-vip and vip-manager hold a floating address by a lease in a consensus store and drop it when
they cannot renew, failing closed; client-go's leader election releases at `renew_deadline` and lets a challenger take
only after `lease` on its own clock, and checks `renew_deadline < lease` but not the retry added to it.
corosync-qdevice gives a two-node cluster a third vote that only breaks ties (`ffsplit`, `lms`). This design takes
qdevice's counting and client-go's timing; a lease alone would take the site's address down whenever the witness is
unreachable, which here buys no safety.

## Consequences
- The 0012/0013 Warpgate cluster on PostgreSQL is withdrawn; the two-node profile is two single-node pods, the
  arbiter in the agent, shared client-facing keys, and the witness (a compare-and-swap record at the core or on site).
- armv7 nodes work as single-node edges do.
- KeyClerk's per-edge structures change as listed; three of them block the profile.

## Changelog
- 2026-11-06: draft 1 (pg_auto_failover), modelled and reviewed adversarially.
- 2026-11-06: draft 2: shared nothing; the election only for the site's address.
- 2026-11-06: draft 3 after the second review, code checks of the agent, Warpgate and KeyClerk, prior art in code,
  and a message-level model of the arbiter.

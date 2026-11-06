# 0028: A second edge node: a cold spare now; two whole edges designed and kept ready; no replicated database

- Status: accepted (maintainer, 2026-11-06), after three drafts, models, two adversarial reviews, code checks, a lab
  and a prior-art pass: the cold spare now (point 1 below), option A designed and kept ready behind a trigger,
  option B rejected. Amends 0012 HA-1 and 0013: the Warpgate cluster on PostgreSQL is withdrawn.
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

## Decision (accepted 2026-11-06)
1. **Now: a cold spare.** A site that wants a second box gets a pre-enrolled spare: the edge's second node in the
   officer's statement (its own enrolment and unlock keys), installed with the same client-facing keys (SSH host key,
   TLS certificate, SSO client, E3 below), kept powered off or with its agent stopped. Taking over is by hand: an
   on-site operator powers the failed node off, starts the spare on the site's address and runs
   `relikey-agent promote` with the site key's promotion statement, which the active node reports as a `break_glass`
   activation (edge protocol 1.5 section 7.3) and the desk records as an incident. The spare pulls the edge's bundle
   and serves within minutes; a node that was replaced returns only as the spare, never beside the active node. No
   arbiter, no witness and no change to KeyClerk's desk: only one node produces at a time, so the desk's per-edge
   records hold as built. A cut-off site keeps working on its last verified bundle in any case (0006, 0011).
2. **Option A, designed and kept ready** (the section "Option A" below, with its models and lab evidence): two whole
   edges sharing nothing that grants, the vote deciding only who holds the site's address. It is built when a
   customer or pilot site needs automatic failover (a takeover without a person on site, in tens of seconds), and not
   before: its cost in KeyClerk's core (per-node removals, comparisons, evidence chains, a decommission path, edge
   protocol 1.6) is then justified by demand. It is built with the four lessons of the appliance pairs: a virtual MAC
   by default, repeated gratuitous ARP, two heartbeat paths between the nodes (one in the kernel, so a busy agent never
   looks dead), and a hardware watchdog.
3. **Option B is rejected.** On two nodes a replicated writer needs three-node consensus and fencing by lease and
   watchdog on bare metal (every product with a replicated writer has a real arbiter: CyberArk's quorum disk,
   Patroni's consensus store); its failover is triggered by exactly the partitions an industrial site has (GitHub,
   21 October 2018: a 43 s partition and an automatic database failover cost a day of reconciliation); the minority
   side loses access; and it is 64-bit only. KeyClerk prefers B for its own footprint (E2); the cold spare costs the
   desk nothing either.
4. **Done regardless:** KeyClerk's two node-2 fixes (the ended notice, phoned unlock; in 0.28.0) and the validity
   window on the site key's promotion statement (KeyClerk, edge protocol 1.6), which the cold spare's takeover uses.

## Prior art: high availability in appliances and access gateways (2026-11-06)
- **Firewall pairs** (FortiGate FGCP, Palo Alto HA, Cisco ASA failover) run two units with no third vote and fight
  split brain only with more heartbeat paths; Fortinet documents "two units, same MAC" as the resulting outage. They
  move a virtual MAC with the address and send repeated gratuitous ARP (FortiGate: five by default).
- **Access gateways** (Teleport proxies, StrongDM gateways, CyberArk PSM pools, Boundary workers) put availability in
  many interchangeable stateless edge nodes; they need their core for new sessions, which a signed, locally verified
  bundle does not.
- **A replicated writer always has a real arbiter**: CyberArk Vault's quorum disk, Patroni's consensus store and
  watchdog, Teleport's and Boundary's consensus backends.
- **Industrial remote access** (Claroty SRA, Secomea, TOSIBOX, Cyolo): none we could check documents on-site paired
  high availability that keeps working offline; the site device is a single gateway. A cold spare matches the
  category; option A would go beyond it.

## Options
| | A: two whole edges (kept ready) | B: a Warpgate cluster, Patroni + etcd (rejected) |
|---|---|---|
| Shared | nothing that grants; the identity clients see (host key, TLS certificate, SSO client) | Warpgate's database |
| The third vote decides | who holds the site's address | whose database is writable |
| Split brain costs | both serve from their own verified bundles; two holders of the address for seconds | two writable databases unless leader key and watchdog hold |
| Access without quorum | yes, every node (0013 point 2 as written) | no |
| Fencing for safety | none | leader key + watchdog, bare metal only |
| Kept whole | | one session history, one evidence chain, one lease credential, desk semantics as built |
| Needs | the node-scoped changes in point 6 (KeyClerk and ReliKey) | PostgreSQL, Patroni, etcd per node; no armv7 |

## Option A, designed and kept ready (built on the trigger in Decision point 2)
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

## Evidence (gathered after draft 3, on the maintainer's request)
- **E2, KeyClerk's position (2026-11-06):** prefers B on footprint, no objection to A, and the promotion statement's
  validity window in both. A costs the desk lasting per-node bookkeeping that only two-node edges use (removals,
  comparisons and evidence chains per node, a decommission path, an edge protocol 1.6 change for evidence), against
  the rule that KeyClerk stays small; B keeps the desk as built. KeyClerk adds the validity window regardless, and
  fixed the two node-2 bugs both options needed (the ended notice, phoned unlock) for 0.28.0.
- **E3, one SSH host key on two Warpgate 0.30.4 nodes: works.** With `ssh.keys: /data/keys` in the configuration and
  a `host-ed25519` file owned by Warpgate's user placed before the first start, both nodes import it into their
  database and present the same fingerprint, kept after a restart. Without `ssh.keys` the file is ignored and each
  node generates its own. Warpgate marks the file import deprecated ("in the future Warpgate will stop reading these
  files"); once imported the file can go, and a later release needs another way to set the key.
- **E1, the address arbiter on an emulated site network (2026-11-06).** A prototype of point 2 (UDP heartbeats, an
  HTTP compare-and-swap witness, retry 2 s, renew deadline 8 s, lease 15 s) in containers on one rootless bridge, a
  client connecting to the site's address every 100 ms; each scenario with a normal client, a client that never
  learns a new MAC for the address (as industrial clients that ignore gratuitous ARP), and a virtual MAC that moves
  with the address. Prototype and results in `tools/ha_models/lab/`.

  | Scenario | normal client | client ignoring gratuitous ARP | virtual MAC |
  |---|---|---|---|
  | the holder dies | 14.4 s, then B | never recovers | 14.3 s |
  | the holder freezes 30 s | 14.2 s | 30.1 s (unexplained recovery, unverified) | 14.3 s, then 7.2 s more while the frozen node still holds the MAC |
  | the nodes stop hearing each other | no gap: the witness keeps A | no gap | no gap |
  | the witness is down, then the holder dies | the address stays down (no majority, by design) | same | not finished |

  Findings: a move costs about the lease (15 s) at these timings; a client that ignores gratuitous ARP needs the
  virtual MAC, and then a frozen holder flaps the MAC on the switch (the review's port-security caveat), so a site
  with such clients needs a watchdog that resets a frozen node; and a returning node took the address for 0.1 s
  before hearing its peer (the prototype started it as holder): the rule is that a starting node holds nothing until
  it has heard its peer or the witness. Not covered: real switches and PLCs (port security, ARP caches kept for
  hours); those need the target hardware or the vendors' documentation.

## Consequences
- The 0012/0013 Warpgate cluster on PostgreSQL is withdrawn. #127 becomes the cold spare: the agent's `promote`
  command and its `break_glass` activation report, the install of a second node with the edge's shared client-facing
  keys (SSH host key through `ssh.keys` as in E3, TLS certificate, SSO client), and an operator guide for the
  takeover. KeyClerk's desk needs no change for it.
- Option A stays designed: its models, lab prototype and evidence are in `tools/ha_models/`. If it is built, KeyClerk's
  per-edge structures change as listed in its point 6, and ReliKey's fleet service admits a second node of an edge
  (an amendment of 0026 point 15, which refuses a second key for an edge today).
- armv7 nodes work as single-node edges do, as a spare or a second node alike.

## Changelog
- 2026-11-06: draft 1 (pg_auto_failover), modelled and reviewed adversarially.
- 2026-11-06: draft 2: shared nothing; the election only for the site's address.
- 2026-11-06: draft 3 after the second review, code checks of the agent, Warpgate and KeyClerk, prior art in code,
  and a message-level model of the arbiter.
- 2026-11-06: evidence E1 to E3 on the maintainer's request: the arbiter on an emulated site network, KeyClerk's
  position, one host key on two Warpgate nodes.
- 2026-11-06: accepted after a prior-art pass on appliances and access gateways: a cold spare now, option A kept
  ready behind a trigger, option B rejected.

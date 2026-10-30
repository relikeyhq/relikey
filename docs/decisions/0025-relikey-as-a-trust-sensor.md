# 0025: ReliKey as a trust sensor: OCSF events, an evidence log, a downgrade feed and FTEF evidence

- Status: accepted (operator, decide loop 2026-10-25), draft 3 after two red-team passes
  (a review record kept with the maintainer). Points 1 and 4 built and proven on full-stack run 3; point 2 is built
  in part (sequence and hash chain); points 3 and 5 are work items.
- Date: 2026-10-25
- Builds on: 0001 points 4 and 5 (no deployment named; ReliKey decides nothing), 0005 (nothing dials the edge), 0009 M1
  (evidence offline), 0022 A4 (the evidence chain), contract C-12; KeyClerk's monitoring shape, its OCSF decision 0018
  and its long-poll decision 0026; the open FTEF specification (0.1); RFC 5848, RFC 9334, RFC 8417, OpenID Shared
  Signals 1.0

## Context
ReliKey stands on the seam where the riskiest access happens: a person, often a vendor's, reaching a system that cannot
defend itself. At that seam it knows, first-hand: who (the broker's subject; for a vendor the partner organisation,
0018), on what authority (the lease, its class and window, the approval), what happened (sessions, recordings, a
session cut by a revoke), what is wrong (drift), and how the seam stands (key exchange per link, attested profile,
exposure test, its own health). Most monitoring sees the network or the endpoint; ReliKey sees the access decision and
its use, joined. A trust- and risk-based monitoring and enforcement system can use that if ReliKey exposes it in
standard forms and its "down fast" reaches the seam quickly.

## Decision
1. **Events: OCSF natively, version pinned (1.6.0).** One JSON line per event: a CloudEvents 1.0 envelope (type
   `relikey.<noun>.<verb>.v<n>`, the subject an entity id) whose data is one OCSF event with its metadata (version,
   product). Classes: Account Change (3001) for an account created or deleted and its sign-ins bound; User Access
   Management (3005) for a role granted, revoked or extended; Authentication (3002, logoff) for a session the agent
   closed; Compliance Finding (2003) for an unmanaged account holding a governed role; Detection Finding (2004) for a
   refused bundle or an ended edge. Later: Authorize Session (3003) for approvals seen at the seam, SSH Activity (4007)
   and RDP Activity (4005) for proxied sessions; API Activity (6003) at debug level only. A finding is emitted when it
   appears and once when it goes, never on every tick. The fields of a monitoring platform's alert-event contract
   (`ts`, `solution`, `event`, `outcome`, `severity`, `reason`, `entity`) ride along as CloudEvents extension
   attributes: one profile among others, never a dependency of the product (0001 point 4) (review 1, 2).
   *Built 2026-10-25:* `agent/internal/events`, the agent's action, finding, refusal and end events, tests and
   mutants.
2. **An evidence log under the events (C-12).** Every record carries its sequence number and id (OCSF
   `metadata.sequence`, `metadata.uid`), the wall time, the trusted time and the skew. Sequence numbers rise within a
   boot epoch kept with the floors (RFC 5848's reboot session id), and records are signed with a forward-secure key
   that evolves, so a compromised edge cannot re-sign its past. The heartbeat carries the chain head hash and the
   sequence number; the core keeps each head as a witness and anchors it (0022 A4); a head that does not chain to the
   last witnessed one is drift on a Tier 0 component. A new contract C-13 carries events to the organisation's store,
   deleted on the edge only after acknowledgement; the buffer is sized per profile (`model/footprint.yaml`), and when
   it is full no new session starts, as for recordings (0009 M1; IEC 62443 SR 2.9, 2.10) (review 3, 4, 5, 6).
   From the second pass:
   - *the epoch link:* the first record of each epoch names the previous epoch's last head and sequence; an
     unannounced epoch or a gap is Tier 0 drift, so restoring an old state or forcing a reboot cannot drop the
     unwitnessed tail silently (the window since the last witnessed head is a stated residual);
   - *the scheme, named:* forward-secure sealing in the manner of systemd's FSS: the verifier seed lives in the core
     only, the first public value is pinned at enrolment, the key evolves per epoch and is erased behind it, and it
     never sits on synced or backed-up storage;
   - *exact bytes:* records are signed as emitted (or in JCS, RFC 8785), after pseudonymisation;
   - *the sequence is durable first:* a high-water mark is persisted in blocks ahead of use; gaps are allowed and
     explained, reuse never;
   - *the acknowledgement is signed:* by the store, naming epoch, sequence and head; the edge deletes only up to it,
     never on an HTTP 200 alone;
   - *a full buffer never blocks protection:* events are aggregated and rate-limited per subject, a tail is reserved
     for revoke, cut, refusal and end records, a "gap" record replaces silent loss, and a full buffer never stops a
     removal, a session cut or break-glass;
   - *two tiers:* a local detail log under its own retention, and the shipped records carrying codes (point 7).

   *Built 2026-10-28 (in part):* the sequence number and id on every record, and a hash chain: each record names the
   sha256 of the line before it, and the head is kept durably in the agent's state before its line is written. A
   verifier holding a head detects a removed, reordered or altered record (`docs/agent.md`). Not yet built: the
   forward-secure signing, the heartbeat head and the core's witness, the epoch link, C-13 and the buffer.
3. **Signals: the existing ones, and only bad news counts without attestation.** ReliKey feeds the adaptive policy's
   `environment` signal (edge cut off, clock set back, bundle no longer verifying) and `behaviour` signal (attempts
   outside a lease, refused approvals, cut sessions). Per-person events stay behaviour signals. ReliKey is listed in the
   platform's sensor register as not attested until TPM attestation exists; a self-reported signal never raises trust
   above medium, and the absence of bad news is not good news (review 7, 13). Omission is caught from outside the
   edge, since a chain cannot show what was never written: the clerk compares the serials it issued with those the
   edge reports applied; the store compares recordings received with session events; heartbeats missing for N
   intervals raise the `environment` signal; the evaluator trusts its own receive time, so late records never buy
   freshness; an edge that shares a release pipeline with the relying party counts as common mode (FTEF principle 7).
4. **Down fast through the bundle, by long-poll.** The clerk stays the one writer of access. The agent long-polls the
   desk (KeyClerk decision 0026: the signed request names the serial held and a wait of at most 55 s; the desk answers
   when this edge's bundle content changes, at once for an unknown serial, one open long-poll per enrolment key, a cap
   per desk), so a revoke reaches the edge in seconds. The agent keeps its jittered pull interval as the floor after an
   immediate answer, and falls back to plain pulls when the desk ignores the wait. Residual: the timing of an answer
   tells an on-path observer that this edge's access changed (review 8). *Built 2026-10-25* against the public edge
   protocol v1.2.0 and its request vectors: an answer that was held or changed the bundle's content is followed by the next
   long-poll at once; an unchanged answer that came at once waits the pull interval.
5. **FTEF: a producer under strict conditions, and a downgrade feed from the core; never a registry.**
   - *attested:* ReliKey is the RFC 9334 Attester. The relying party's own verifier issues the `attested` item; ReliKey
     never does (FTEF 5.3, 7.1 point 3) (review 9).
   - *self-measured:* only where a partner domain operates the edge. Evidence is signed with a separate evidence key,
     certified by the enrolment key, under its own domain-separation label, and published for the relying party
     through federation metadata (review 10).
   - *observed:* `second-party` is the relying party itself, so only the relying party that operates the edge labels
     an item `observed`. A copy shared elsewhere is advisory. A "peer-observed, adverse only" extension class is a
     proposal for FTEF 0.2, not used before (review 11).
   - *positive evidence from an edge counts only when attested;* without attestation the edge is a down-only sensor
     (review 13).
   - *an adverse item's `covers`* names only the access service at this seam, so one edge cannot cancel a vendor's
     assessed evidence for its whole organisation; a partner-level adverse item needs a confirmed incident or a
     threshold across several subjects, so one stolen credential cannot frame a vendor (review 14).
   - *downgrades:* the core, never the edge, transmits Security Event Tokens signed with a key published in federation
     or Shared Signals metadata. A registry takes them as advisory input under its own allow-list and rate limits and
     downgrades on its own triggers (FTEF section 9) (review 12).
   - ReliKey never sets `scope`, never decides or publishes partner states (a move up needs a named decider, FTEF 6.4,
     6.6), and never shares attack paths.
6. **Personal data, minimised.** Pseudonymised identifiers are still personal data (GDPR Art. 4(5), Recital 26). The
   feeds name the bastion account and lease ids; a keyed pseudonym per tenant, rotating, with re-identification only
   in the core, replaces the account name when the evidence log lands. The purpose is security, never staff
   performance; retention is limited; the systematic monitoring of vendor technicians needs a DPIA by the deploying
   organisation. FTEF items speak of organisations only; a sole-trader partner is personal data too (review 15).
7. **Detail stays local.** Drift detail (which unmanaged account holds which role on which target) and the full text
   of a refusal stay in the local drift report and the detail log; the feeds carry reason codes and levels (FTEF 7.1
   point 4) (review 16). An event for a change the agent itself made names the account and the role it granted or
   removed: that is what the event is, and it stays in the organisation's own store. Custom event types and the
   evidence-log format are published as a versioned, neutral profile, so no one consumer owns them.
8. **Order:** OCSF events (built); the long-poll (built); the evidence log with C-13; Shared Signals from the core;
   FTEF evidence items once FTEF 0.2 opens (0.1 is frozen for new proposals).

## Consequences
- Any SIEM, risk engine or registry can read ReliKey (OCSF, Shared Signals with Security Event Tokens, FTEF,
  Prometheus); no consumer is privileged.
- Until the rest of the evidence log exists, events are sequenced and hash-chained but not signed or witnessed, so a
  chain alone shows tampering only to a verifier that holds a head; they also name bastion accounts, and stay in the
  organisation's own store meanwhile.
- A signed chain on the edge is something PAM products' audit streams do not offer (they send events or syslog);
  that is the sensor's difference, and its cost is the forward-secure key handling.

## Consider the opposite
A ReliKey-specific monitoring API would be quicker and fit our needs exactly. Against it: a sensor's value is that any
trust system can read it; a private API makes one platform the only consumer, the lock-in ReliKey's role seams (0023)
exist to avoid.

## Changelog
- 2026-10-25: accepted (operator); points 2, 3 and 5 are work items.
- 2026-10-25: draft 3 after the second red-team pass: point 2 gains the epoch link, the named forward-secure scheme,
  exact bytes, a durable sequence, a signed acknowledgement, a reserved tail and two tiers of detail; point 3 regains
  the omission cross-checks; point 7 says what change events name. Code fixed: only a verified bundle counts as a
  change for the long-poll, "held" needs half the wait, the refusal event carries a code.
- 2026-10-28: point 2 built in part: event sequence numbers and a hash chain on the edge.
- 2026-10-25: point 4 built (the long-poll, KeyClerk 0026).
- 2026-10-25: draft 2 after the review (amendments 1 to 16); point 1 built.
- 2026-10-25: proposed (decide loop on ReliKey as a trust sensor).

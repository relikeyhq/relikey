# 0008: Edge hardening after red team 1 - admin API, the P-B path, break-glass, phoned unlock

- Status: accepted (decide loop 2026-10-23, H1 to H4; operator)
- Date: 2026-10-23
- Record: decide loop (record kept with the maintainer); findings RT-5, RT-7 to RT-12 of
  red team 1 (record kept with the maintainer). Builds on 0007.
- Corrected 2026-10-23: the admin routes exist under `/_warpgate` as well as `/@warpgate` (found while building U-08).
- Amends 0002 (break-glass), 0003 (point 5, injection), 0004 (sessions end with the lease), 0006 (levels 4 and 5).

## Decision
1. **Admin API (H1, RT-5).** A separate minimal filtering proxy on the edge terminates TLS on the user HTTPS port and
   forwards everything except the admin UI and API to Warpgate on loopback. Warpgate mounts its own routes under both
   `/@warpgate` and `/_warpgate` (warpgate-protocol-http/src/lib.rs), so the proxy refuses `/@warpgate/admin*` and
   `/_warpgate/admin*`, matched after percent-decoding and path normalisation; a test sends both forms. It holds only
   the TLS certificate, never an admin token, and passes WebSockets (web SSH and RDP) and HTTPS targets intact. A separate admin listener is
   proposed to Warpgate upstream (docs/upstream.md U-08); the proxy goes when it lands.
2. **P-B path (H2, RT-7).** A person reaches an LDAP-only system through a Warpgate target - its web UI as an HTTPS
   target, a thick client on a jump host behind an RDP target - and types the lease credential; the session is
   recorded and the wrapper rule holds. "The bastion injects the credential" is withdrawn until Warpgate can inject
   per-user credentials (U-09, building on Warpgate #2762).
3. **Break-glass when the edge is dead (H3, RT-8).** Each system keeps one legacy-native local account (its console or
   local administrator). The agent sets every new value at random, encrypts it to two custodians' public keys (both
   needed to read it) and keeps it until the escrow acknowledges receipt - it never rotates into the void. Using it
   needs physical presence; the system's own log shows the use on recovery and KeyClerk opens an incident. This is a
   recorded exception to KeyClerk 0011a: it is not a broker membership and grants nothing outside that one device.
4. **Phoned unlock (H4, RT-10), assured edges only.** The person presents their registered hardware key on site; the
   challenge shows that key's fingerprint and the code unlocks only that key. The approver is on the edge's approver
   list, is never the person, and calls back to a registered number. The unlock key is per edge, in the TPM. Wrong
   codes add delay instead of a hard lock-out; counters survive a reboot.
5. **Set by precedent, not asked.**
   - *Sessions end with the lease (RT-11):* the agent terminates sessions at lease end or revocation; every target has
     a maximum session duration in Rego; an end-to-end test proves it.
   - *Key enrolment (RT-12):* registering an operator's hardware key is a governed change with a second key, with
     attestation where the key offers it, one key per person, unique across persons, PIN or user verification required.
   - *Rollback and replay (RT-9):* on assured edges the serial floor and used-lease ids live in the secure element's
     monotonic counter; basic edges refuse carried leases; carried leases use their own counter space, short windows,
     one per person per edge; the core alarms when an edge stops pulling bundles.

## Consequences
- New edge component: the filtering proxy (`model/components.yaml`), until U-08.
- The model check now refuses a pattern whose consecutive path steps are not allowed flows (RT-17, part).
- Upstream items U-08 (separate admin listener) and U-09 (per-user credential injection) are to be proposed; U-08 is
  approved by the operator in principle, its issue text needs the operator's go.
- The medium and low red-team-1 findings are decided in 0009 and 0012.

## Changelog
- 2026-10-25: point 1's filtering proxy is to be built now (decide loop, stack attack E6: the shipped compose
  publishes the admin paths); the agent moves to Warpgate's admin listener if warp-tech/warpgate#2782 lands.

# 0009: Evidence offline, lease secrets for the person only, the local access window, scope - after red team 1

- Status: accepted (decide loop 2026-10-23, M1 to M4; operator)
- Date: 2026-10-23
- Record: decide loop (record kept with the maintainer); findings RT-13 to RT-21 of
  red team 1 (record kept with the maintainer). Builds on 0007 and 0008.
- Amends 0003 (who can read a lease credential), 0005 (the edge keeps a recording store; footprint corrected), 0006
  (the local access port).
- Amended 2026-10-25 (operator, decide loop on 0014 Q-1): point 2, for named applications behind the sign-in gateway.

## Decision
1. **Evidence when the edge cannot deliver it (M1, RT-13).** Each hardware profile has a sized local recording store
   (`model/footprint.yaml`, counted in the edge's disk). Warpgate streams recordings to the organisation's store; what
   it could not deliver, the agent backfills when the uplink returns, chaining each recording's hash in the edge log
   and deleting it only after the core acknowledges (C-12). Below the store's free-disk floor no new recorded session
   starts: the edge fails closed on evidence. Break-glass (0008) is unaffected. The evidence store is now required
   (F-09, F-13, F-21). Warpgate's own upload does not retry; that is upstream item U-10.
2. **Lease credentials for the person only (M2, RT-14).** When a person registers their hardware key (a governed
   change, 0008), their passkey also derives a key pair through WebAuthn PRF (hmac-secret on FIDO2 keys); the public
   half is registered in KeyClerk. The agent encrypts a P-B credential to it; the desk relays ciphertext and cannot read
   it. Where the system binds once per login, the agent rotates the credential right after the first successful bind
   and alerts on any bind without a matching session of the holder. There is no fallback to a desk key: an
   authenticator without PRF cannot receive P-B credentials.
   *Amendment (2026-10-25), the sign-in gateway (0014 part A).* M2 holds for P-B and P-D, and it is the gateway's
   default too: its local-login converter stores no credential for a person. One exception, per application: where an
   application's only sign-in is a local account per person, the officer's ceiling may name that application, and the
   gateway may then hold a credential for one lease's session only. It is set at session start, never shown to the
   person, rotated at session end and at lease end, never kept past the session and never readable by the desk. Each
   such application is a residual on its installation checklist, with the owner's name.
3. **The local access window (M3, RT-15).** Link-up on the edge's dedicated wired access port opens the local listener
   for a window set in Rego (default 4 hours), and the event is logged. The window serves SSH only - Warpgate SSH (F-16)
   and the agent's lease endpoint (F-17) - never HTTP. No Wi-Fi unless a deployment records the purpose. Entering still
   needs a visit lease, the phoned unlock or break-glass (0006, 0008).
4. **Scope (M4, RT-20).**
   - New pattern **P-D**: a machine's own panel (HMI) that signs people in with an LDAP bind. The panel binds to the
     facade; the lease credential reaches the person's phone encrypted to their passkey (point 2) and is rotated after
     the first bind. It is a physical path (`medium: physical`, F-15), not a network one, so the wrapper rule (0002)
     holds. Offline: break-glass only, until an offline hand-over exists (R-11).
   - A hardware appliance's web UI is P-C online, break-glass offline.
   - Proprietary thick clients run on a jump host behind an RDP target (0008).
   - Vendor back doors - cellular modems, TeamViewer-like tools, vendor VPNs, USB and serial cables outside the edge -
     are out of scope. The installation checklist (`docs/installation-checklist.md`) inventories every non-IP path;
     the system's owner disables it or records the risk.
5. **Set by precedent (not asked).**
   - *The agent holds policy (RT-16):* the edge runs the same compiled policy module KeyClerk ships, as one signed
     WebAssembly artifact in the bundle, and a shared conformance test set runs against KeyClerk and the agent.
   - *The model check (RT-17):* it now refuses a loopback-only port that is also served to a network, a loopback flow
     across hosts, a physical path from anything but a person, and deployment names in the docs; it counts the
     recording store; flows for updates, time and name resolution, escrow and the local window are modelled. Runtime
     enforcement comes with the composition (R-03), not from the YAML. The new loopback rule caught one design error
     at once: the agent would have rotated passwords over the LDAP port the legacy system binds to; the agent now uses
     the facade's admin API on loopback (F-08).
   - *Footprint (RT-18):* Warpgate is about 100 MB on disk and glibc-linked, not static; KeyClerk is amd64-only, so a
     single-box core plus edge needs an amd64 host. Reference products stay open (R-10).
   - *Supply chain (RT-19):* images pinned by digest with provenance verified at pin time and on the edge; edges pull
     through the core's update mirror (R-16) against a signed update manifest whose key is separate from the
     lease-signing key; staged rollout (C-11).
   - *Inconsistencies (RT-21):* fixed in the records they concern (0002, 0004, C-04, C-05, README).

## Consequences
- On the switch profile the recording store is small (90 MB): offline, graphical sessions stop soon. That is the price
  of evidence on 1 GB of flash, and is stated to the system's owner.
- KeyClerk needs: PRF-derived person keys at key enrolment, ciphertext relay on the desk, signed policy modules in
  bundles, approval proofs switched on in the shipped configuration.
- Still open: R-01 to R-16 except those closed by records.

## Changelog
- 2026-10-25: point 2 amended for the sign-in gateway: no stored person credential by default; a per-session
  credential only for an application the officer's ceiling names, recorded as a residual (decide loop on 0014 Q-1).
- 2026-10-23: accepted (decide loop, M1 to M4).

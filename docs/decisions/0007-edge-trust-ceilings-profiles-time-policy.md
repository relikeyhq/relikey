# 0007: Edge trust - ceilings, hardware profiles, time, visit windows, remote reach, policy in Rego

- Status: accepted (decide loop 2026-10-23, D1 to D5, after red team 1; operator)
- Date: 2026-10-23
- Record: decide loop (record kept with the maintainer); findings RT-1 to RT-4 and R-14 of
  red team 1 (record kept with the maintainer).
- Operator, 2026-10-23: "intent through opa must be able to change this config easily".
- Amended 2026-10-23 (R-18, operator): point 2's ceiling is officer-signed **data** (`kc-edge-ceiling-v1`, rising serial,
  the officer's Ed25519 key) read by KeyClerk's shipped `ceiling.rego` in the core and in the agent (KeyClerk 0014);
  no officer-written code runs anywhere. Everything else in point 2 holds.
- Amends 0005 (the edge decides only with signed policy, inside a ceiling) and 0006 (visit-lease windows, the FIDO
  key correction).

## Context
Red team 1 found that one core signing key opened every edge (RT-1), that a stolen or swapped edge leaked everything
(RT-2), that an offline edge trusted a wall clock anyone can set (RT-3), and that visit leases died at the 1-hour
privileged horizon before the visit (RT-4). Remote reach for people off site was undecided (R-14).

## Decision
1. **Policy in Rego, compiled to WebAssembly, run inside the agent (no OPA daemon).** Every edge decision - admitting a
   session, holding a visit lease, offline validity, remote reach - is Rego signed in the core and delivered in the
   bundle, evaluated in process (a Wasm runtime of a few MB, e.g. wazero; the OPA binary is 60 MB). Changing intent is
   new signed Rego, not an edit on the edge. This replaces 0005's "the edge decides nothing": the edge decides only with
   policy signed elsewhere, inside a ceiling it cannot widen.
2. **Per-edge ceiling (D1).** Each edge holds a ceiling - which persons or roles, which targets, the maximum lease, the
   maximum offline validity, the allowed lease classes, the hardware profile, the remote-reach mode and ports - written
   in Rego and signed by that edge's own officer with a hardware key (KeyClerk 0013 D3 child ceiling). The edge admits
   only what both the core's policy and the ceiling allow: core policy can narrow, never widen. Only the officer's
   signature changes a ceiling; the officer is not a core administrator.
3. **Two hardware profiles (D2).** *Assured*: a TPM or secure element, storage encrypted and sealed to it, signed or
   measured boot; it may hold offline visit leases, the phoned-unlock key and break-glass material. *Basic*: no secure
   hardware the edge can use (most switch container hosts, an ordinary laptop); no offline grants, no break-glass
   secrets, a short offline validity - it enforces what the core currently signs. The ceiling names the profile;
   hardware facts reach the policy from attestation as input, never from configuration.
4. **Time (D3).** The edge never believes a time earlier than the newest signed timestamp it has seen (a bundle's issue
   time, its own last log entry). Offline validity is also capped by time elapsed on a counter that cannot be set back
   since the last trusted time (the TPM clock on assured edges, the boot counter otherwise). A hardware clock is used
   where present. Setting the clock back is refused; setting it forward ends leases early (fails closed).
5. **Visit-lease windows (D4).** A visit lease carries its own signed window, independent of the bundle's class
   horizon, bounded by the ceiling's maximum offline validity and the time rules, on assured edges only; one edge, one
   key, named targets. The default maximum lives in the shipped Rego (72 hours) and is changeable by policy. Past its
   class horizon the agent ends the leases of that class, not every lease (corrects C-04).
6. **Remote reach (D5).** Off by default: people on the site network reach the bastion directly. A remote-reach plugin
   - a tunnel the edge opens, or a NetBird peer where the organisation already runs NetBird - carries bastion user
   sessions only, never the host and never Warpgate's admin API (which shares the user listener today, RT-5, so a
   filtering proxy stands in front until Warpgate offers a separate admin listener). Mode and ports are in the ceiling.

## Corrections to earlier records
- 0006 level 2 said a pre-staged visit lease with an `sk-ssh-ed25519` key "works with Warpgate as it is today". It does
  not: Warpgate's SSH library (russh 0.63) accepts no FIDO key types (russh #760; docs/component-facts.md). Until that
  is improved upstream (docs/upstream.md U-01), the operator's hardware key holds a non-exportable `ssh-ed25519` key
  (OpenPGP applet, touch required), which Warpgate accepts. 0006 also said "four levels" and lists five.
- 0004 point 3 named only `AccessRolesAssign` and `ApproveSessions`; installing a visit key needs `UsersEdit` (RT-6).
  The agent is treated as a full Warpgate administrator in the threat model; profile and storage rules above protect it.

## Consequences
- Contracts: C-04 corrected (class horizons); a new contract C-10 for the ceiling (`model/contracts.yaml`).
- The edge agent (R-08) is a small static binary embedding a Wasm runtime for signed Rego.
- Further red-team-1 findings are decided in 0008, 0009 and 0012; R-16 (ReliKey on an operator's PC).
- Residuals: a visit lease cannot be revoked while its edge is cut off; a basic edge protects nothing against someone
  holding it; a core compromise still grants anything inside every ceiling.

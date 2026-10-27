# 0006: Working without a network, and break-glass

- Status: accepted (operator, 2026-10-23: as amended by 0007, 0008 and 0009 after red team 1)
- Date: 2026-10-23
- Amended by 0009: the local access port opens a logged, SSH-only window on link-up.
- Amended by 0008: level 4 hardened and assured-only; level 5 when the edge is dead is a legacy-native escrowed account.
- Amended by 0007: level 2 cannot use `sk-ssh` keys yet (russh #760; a non-exportable `ssh-ed25519` key on the
  hardware key instead); visit leases carry their own signed window on assured edges only; five levels, not four.
- Operator, 2026-10-23: "old network equipment will be a common use case as well, often action is needed WHEN there is
  no network, an operator that has to come on site will not have a portable engine, or can he? [...] there should thus
  be a breakglass".

## Context
The systems ReliKey wraps include network equipment, and the moment someone must touch it is often the moment the
network is down: the edge cannot reach the core, the operator on site cannot reach Keycloak, nobody can approve live.
Decision 0005 already keeps open leases running to the bundle's horizon; it does not let a new person in.

## The position: carry decisions, never the power to decide
An operator can carry a "portable engine", but it must carry signed decisions, not the ability to make them. A laptop
holding KeyClerk's signing keys is a skeleton key: whoever steals it grants themselves anything, at every edge. What
travels is a lease KeyClerk signed in advance, bound to the operator's own hardware key, for one edge, named targets and
a time window. The edge verifies it with KeyClerk's public key alone. Losing the laptop or the phone loses nothing; losing
the hardware key loses one window, and the lease dies with it.

## Decision
Five levels, tried in order; each one the edge can check without the core.

1. **Cut off, lease already there** (0005): leases in the last bundle run to the horizon; sessions they cover are
   approved at the edge.
2. **Pre-staged visit lease** (C-06). A planned visit is requested in KeyClerk while the edge is still reachable, with
   the second key policy demands. KeyClerk signs it into the edge's bundle; the agent installs the operator's FIDO SSH
   public key (`sk-ssh-ed25519`, held on their hardware key) as a Warpgate credential and a role assignment whose
   `expires_at` is the window's end. On site, with no network at all, the operator signs in to Warpgate over SSH with a
   touch of the key; Warpgate checks the public key locally. This works with Warpgate as it is today.
3. **Carried visit lease** (C-07, R-11). The edge was already cut off when the visit was planned. KeyClerk signs the
   lease to the operator instead; the operator carries it (a file on the laptop or phone) and presents it to the agent
   on the edge's local access port, proving possession with the same hardware key. The agent checks KeyClerk's
   signature, the edge id, the window and the bundle serial floor, then installs the credential as in level 2.
4. **Phoned unlock** (C-08, R-13). Nothing was planned, but a phone works. The edge shows a challenge (edge id, target,
   person, nonce); a second person with KeyClerk access approves it and reads back a short response code bound to that
   challenge and a short duration. Single use, rate-limited, and the approver must not be the person on site.
5. **Break-glass** (C-09, R-06). Nothing works: no lease, no phone. Each legacy system keeps one sealed local
   credential that nobody knows alone: it is held in the organisation's password manager, readable offline, under dual
   control (two custodians, each holding part). Using it is an incident, not a workflow: the edge records it, the agent
   rotates the credential as soon as it can, and KeyClerk opens a review when the edge reconnects. No paper copies, no
   sealed envelopes, no show-once codes on a sheet.

Everything at levels 2 to 5 is recorded on the edge in a hash-chained local log and delivered when the edge reconnects;
the edge keeps undelivered evidence until it is acknowledged (amends 0005 point 5).

## Local reach
When the network is down, the operator reaches the edge directly: a local access port (a dedicated Ethernet port, a
USB network gadget, or a short-lived local Wi-Fi network, all off by default), never the production network. For
network equipment whose only way in is a serial console, the edge offers the console as a Warpgate target (R-12), so the
same lease, recording and break-glass rules apply.

## Consequences
- The edge must sit on a device that survives the equipment it protects: an edge on the very switch that is broken
  cannot help. Deployment guidance says so; for network equipment the edge goes on a small board or a separate
  management switch with a console cable.
- Level 2 is the recommended practice and costs nothing new; levels 3 and 4 need agent work (C-07, C-08) and a red team
  of their own before they ship; level 5 must be tested with each deployment (a break-glass drill).
- RDP and web targets offline: Warpgate's web sign-in needs the broker. Until R-11 settles a local sign-in for them,
  offline access is SSH and serial; RDP and web wait for the core or break-glass.

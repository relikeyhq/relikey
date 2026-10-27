# 0012: Open decisions after the agent build (decide loop, 2026-10-23)

- Status: accepted (operator, decide loop 2026-10-23; each outcome below was the operator's answer or a default the
  loop stated from a precedent: R-04, R-05 (capable by policy, secure by default), R-06 (0008 H3, no paper recovery),
  R-07 (KeyClerk 0013 D4), R-09 (0010), R-11 (KeyClerk 0014c), R-13 (KeyClerk 0014c), AG-14, AG-18)
- Closes R-01 to R-07, R-09, R-11 to R-13, R-15 to R-17, R-19, the duplicate R-16 (now R-20), and the agent red team's
  open AG-11, AG-14, AG-18, AG-20. R-10 (reference hardware) stays open.
- Amended by 0013 (2026-10-24): HA-1's witness is a profile setting, the core when connected and a device on site
  under DDIL, with break-glass promotion as the last resort; the bare PostgreSQL advisory lock below is superseded.

## Outcomes
| # | Decision | Outcome |
|---|---|---|
| KC-4 | Seal the ceiling and the enrolment statement (KeyClerk 0014d, kc-edge-ceiling-v2 / kc-edge-officer-v2): one signing mode, exact bytes only | adopt 0014d now |
| AG-11 | A lease's target is not enforced separately: a Warpgate role reaches every target bound to it | agent enforces, fail closed |
| AG-14 | Flash wear: the state is rewritten on every new serial | floors every serial, bundle only on content change |
| AG-18 | The ended notice carries no time or serial: a captured notice replays (it can only end the edge) | accept; never reuse an ended edge id |
| AG-20 | Shadow (canary) agent next to the enforcing one: its own enrolment at the desk | follower shadow reads the stored bundle |
| OP-1 | End-to-end on a lab host with real Warpgate and Keycloak | now, v1 formats |
| OP-2 | arm64/armv7 test runs: qemu-user on a shared build host, or real hardware, or a lab box | arm64 lab box with qemu-user there for armv7 |
| R-01 | Does the core keep OpenBao at all? | no OpenBao in ReliKey; the organisation's via Warpgate's secret backend, amended: operator: where something should be more secure or Warpgate cannot yet do it, we contribute it upstream as a PR rather than add a component |
| R-02 | Which LDAP facade on the edge? | lldap + compatibility test set |
| R-03 | One container with three processes, or a pod of three? | pod of pinned upstream images; single image only where the host takes one container |
| R-04 | Plain LDAP (no TLS) on an isolated link? | refused by default; per system by policy |
| R-05 | Header-based identity for web apps (P-C)? | off by default; per app by policy behind the bastion |
| R-06 | Break-glass escrow pattern (dual control, offline reading) | KeyClerk escrow to two custodians' keys (0008 H3); never paper; drill per deployment |
| R-07 | Core broker standalone, or broker to the organisation's broker? | both; brokering recommended (KeyClerk 0013 D4) |
| R-09 | New sign-ins while the edge cannot reach the core | broker sign-in waits for the core; on site via 0006 levels |
| R-11 | Offline carried lease presentation; RDP and web offline | SSH first (carried lease, SSH key proof); RDP and web offline deferred |
| R-12 | Serial consoles of network equipment as targets | yes: SSH target to a local sshd forced command per console line |
| R-13 | Phoned unlock code format | settled by KeyClerk 0014c |
| R-15 | P-B: one holder per account at a time, rotation at session end | one holder per account; rotate at session end, else lease end |
| R-16 | ReliKey on an operator's PC | trial + single-site (basic) and assured portable; one engine, attested profile, amended: operator: both uses. One binary everywhere; the profile is proven not configured: assured only when the officer's ceiling says assured AND the TPM attestation (KeyClerk 0016) proves it; config may only lower it. Assured portable = TPM, measured boot, disk encryption, operator not local admin. |
| R-17 | Graphical targets and edge profiles | switch profile terminal and LDAP only; graphical on small-board+; 5 fps recording |
| R-19 | Phoned-unlock X25519 key on assured edges (TPM has no Curve25519) | P-256 inside the TPM (kc-unlock-v2) |
| R-20 | Which registry mirror serves edge updates (model id was a duplicate R-16) | zot in the core, pinned digests only |
| HA-1 | High availability, optional but supported (operator): which layers and how (edge Warpgate cluster with shared PostgreSQL, agent with two nodes, core Keycloak and KeyClerk) | layered HA profile, amended: operator: HA is optional but supported |

## Principles recorded with it
- **Upstream first** (operator, R-01): where something should be more secure, or Warpgate cannot yet do it, ReliKey
  contributes it upstream as a pull request rather than adding a component.
- **HA is optional but supported** (operator, HA-1): a two-node edge profile on small servers (Warpgate cluster on
  PostgreSQL, lldap on it, a floating address, the agent active/standby by a PostgreSQL advisory lock, the standby
  verifying into its own floors); the core by each component's own clustering; never on the switch profile.
- **One engine, attested profile** (operator, R-16): the same binary everywhere; a profile is proven, not configured;
  configuration may only lower it.

## Asked of KeyClerk
0014d adopted (KC-4); kc-unlock-v2 with P-256 inside the TPM (R-19); two enrolment keys per edge for the HA profile
(HA-1); refuse re-enrolment under an ended edge id (AG-18).

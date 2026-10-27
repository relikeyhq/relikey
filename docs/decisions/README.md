# Decision records

ReliKey's own design decisions. Open questions live in `model/open-decisions.yaml` until a decide loop settles them.

| # | Decision | Status |
|---|---|---|
| [0001](0001-a-distribution-not-an-engine.md) | ReliKey is a distribution, not a new engine | accepted |
| [0002](0002-the-only-path-in-is-the-wrapper.md) | The only path in is the wrapper | accepted |
| [0003](0003-ldap-lease-credentials.md) | An LDAP-only system gets lease credentials, never a person's password | accepted |
| [0004](0004-keyclerk-drives-the-bastion.md) | KeyClerk drives the bastion; Warpgate enforces and records | accepted |
| [0005](0005-a-small-edge-and-a-shared-core.md) | A small edge next to the system, a shared core elsewhere | accepted |
| [0006](0006-working-without-a-network.md) | Working without a network, and break-glass | accepted |
| [0007](0007-edge-trust-ceilings-profiles-time-policy.md) | Edge trust: ceilings, hardware profiles, time, visit windows, remote reach, policy in Rego | accepted |
| [0008](0008-edge-hardening-after-red-team-1.md) | Edge hardening: admin API proxy, the P-B path, break-glass, phoned unlock | accepted |
| [0009](0009-evidence-secrets-local-access-scope-after-red-team-1.md) | Evidence offline, lease secrets for the person only, the local access window, scope | accepted |
| [0010](0010-keycloak-and-warpgate.md) | Keycloak and Warpgate: authentication only, KeyClerk decides access | accepted |
| [0011](0011-the-edge-agent.md) | The edge agent: Go, one static binary, signed decisions only; slice 1 | accepted |
| [0012](0012-open-decisions-after-the-agent-build.md) | Open decisions after the agent build (decide loop): HA, packaging, profiles, P-B, consoles, mirror | accepted |
| [0013](0013-ha-witness-per-profile.md) | The HA witness is a profile setting: the core when connected, on site under DDIL | accepted |
| [0014](0014-sign-in-gateway-role.md) | A sign-in gateway role in the one engine: LDAP, local login (part A) or Kerberos (part B) for apps that take nothing modern | part A accepted, part B proposed |
| [0015](0015-core-composition.md) | The core as one pod: Caddy in front, the broker's PostgreSQL, everything else on loopback | accepted |
| [0016](0016-solution-agnostic-contracts-by-role.md) | Contracts by role, so other clerks and bastions can fill them; optimised for KeyClerk and Warpgate | accepted |
| [0017](0017-a-neutral-edge-decision-interface.md) | The edge-decision interface: the edge protocol's security profile | accepted |
| [0018](0018-vendor-sign-in-through-their-own-provider.md) | A vendor's people sign in through the vendor's own identity provider, pinned by subject | proposed |
| [0019](0019-lease-gated-network-reach.md) | Protocols the bastion cannot carry: through a plant engineering workstation, not network reach | accepted |
| [0020](0020-read-only-protocol-mediator.md) | Read-only diagnostics: a diagnostic workstation on a read-only conduit, not a mediator in ReliKey | accepted |
| [0021](0021-legacy-telemetry-modernisation.md) | Legacy telemetry and certificates: recipes, an inventory and the edge's own certificates, not a relay or CLM | accepted |
| [0022](0022-crypto-agility-and-post-quantum.md) | Crypto agility and post-quantum: lead time first, the inventory proved, formats by KeyClerk | accepted |
| [0023](0023-role-seams-in-the-agent.md) | Role seams in the agent: the core speaks to a clerk and a bastion, not to KeyClerk and Warpgate | accepted |
| [0024](0024-legacy-client-jump-target.md) | Logons the bastion cannot carry (telnet, serial, old TLS): console servers, a re-terminator, a legacy client jump target (P-F) | accepted |
| [0025](0025-relikey-as-a-trust-sensor.md) | ReliKey as a trust sensor: OCSF events, an evidence log, a downgrade feed and FTEF evidence | accepted |
| [0026](0026-federated-observability-and-fleet-management.md) | Federated observability and fleet management: ReliKey's own, tiered, tighten-only below the parent | accepted |
| [0027](0027-public-engine-source-on-github.md) | The engine's source of record is its public repository; a private companion keeps the rest | accepted |

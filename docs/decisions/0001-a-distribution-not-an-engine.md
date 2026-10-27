# 0001: ReliKey is a distribution, not a new engine

- Status: accepted (operator, 2026-10-23: as amended by 0007, 0008 and 0009 after red team 1); point 2 amended by
  0014 part A (2026-10-25)
- Date: 2026-10-23

## Context
Legacy systems that can only check a password (an LDAP bind, a local account, a database login) cannot be given
passkeys, approvals or session evidence. The parts to wrap them exist: Keycloak brokers identities and holds passkeys,
KeyClerk decides access and keeps its lifecycle, Warpgate proxies and records SSH, RDP, VNC, database, Kubernetes and
HTTPS sessions, OpenBao rotates credentials. No open project packages them for this purpose (docs/prior-art.md).

## Decision
1. ReliKey composes upstream images pinned by version and digest (`model/components.yaml`). It forks none of them and
   patches none of them; it configures each only through its documented configuration and API.
2. Behaviour that needs code lives where it belongs: governance in KeyClerk (as target plugins, KeyClerk 0002),
   protocol handling in Warpgate. Two exceptions, both roles of one engine: the edge agent (0005), which applies
   signed decisions and makes none, and the sign-in gateway (0014 part A), which presents a credential only on a
   verified lease, behind the bastion. A gap goes upstream or into a KeyClerk plugin, not into a ReliKey fork.
3. ReliKey holds: the model (components, flows, patterns, contracts), the shipped configuration with secure defaults,
   the composition (deploy/), the end-to-end tests that prove the contracts, and its decision records.
4. ReliKey names no deployment, customer or site; a test enforces it (as in KeyClerk 0001).
5. ReliKey is not an identity provider (the broker is) and not a second identity control plane (KeyClerk is the only
   writer of access, KeyClerk 0013 D2).
6. Capable by policy, secure by default: anything a deployment may need is reachable through configuration and policy;
   the shipped defaults are the secure ones, and turning a capability on records its purpose.

## Consequences
- ReliKey's version is a set of pins plus its configuration; upgrading a component is a pin change with the end-to-end
  tests as the gate.
- Contracts C-01 to C-04 (`model/contracts.yaml`) are honoured by the edge agent (0005) applying KeyClerk's signed
  bundles; the signing side is KeyClerk 0013 D3.
- Licence: EUPL-1.2 (operator, 2026-10-24; was Apache-2.0, aligned to KeyClerk and the estate product class). The
  composed images keep their own licences (NOTICE).

## Changelog
- 2026-10-25: point 2 amended: the sign-in gateway (0014 part A) is the second exception beside the edge agent.

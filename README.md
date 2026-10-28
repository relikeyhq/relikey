<h1><picture><source media="(prefers-color-scheme: dark)" srcset="brand/wordmark/relikey-lockup-dark.svg"><img alt="ReliKey" src="brand/wordmark/relikey-lockup-light.svg" height="56"></picture></h1>

<p>
  <a href="https://github.com/relikeyhq/relikey/actions/workflows/ci.yml"><img src="https://github.com/relikeyhq/relikey/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/relikeyhq/relikey"><img src="https://api.scorecard.dev/projects/github.com/relikeyhq/relikey/badge" alt="OpenSSF Scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-EUPL--1.2-blue" alt="Licence: EUPL-1.2"></a>
</p>

Modern access in front of systems that cannot have it themselves.

Many organisations depend on a system that can only check a password: an application that binds to LDAP, a server
with local accounts, a database console. ReliKey is a small appliance placed next to such a system. It becomes the
only way in: people sign in with a passkey, access is granted for hours with a second key where it matters, every
session is recorded, and the system itself stays unchanged.

ReliKey is a distribution, not a new engine (decision 0001). It has two tiers (decision 0005): a small **edge** that
runs as a container on a switch's app-hosting or a Raspberry Pi class board next to the system, and a shared **core**
that serves many edges. It composes pinned upstream components:

| Component | Tier | Role |
|---|---|---|
| [Keycloak](https://github.com/keycloak/keycloak) | core | Identity broker: passkeys, sessions, brokering to the organisation's IdP |
| [KeyClerk](https://github.com/keyclerk/keyclerk) | core | Governance: who may reach what, until when, with whose second key |
| [Warpgate](https://github.com/warp-tech/warpgate) | edge | Bastion: SSH, RDP, VNC, databases, Kubernetes and HTTPS, recorded |
| [OpenBao](https://github.com/openbao/openbao) | core, optional | Credentials: target secrets |
| Edge agent | edge | Applies KeyClerk's signed leases on the edge; a purpose-built Go binary that decides nothing |
| Fleet service | core | Inventory of the edges, enrolment by code and an officer's passkey, the officer registry (decision 0026) |
| [lldap](https://github.com/lldap/lldap) | edge | The directory an LDAP-only system binds against (decision 0012) |

## How it encapsulates
- **P-A, protocol bastion.** Sessions go through Warpgate; a KeyClerk lease becomes a Warpgate role that expires with
  it, and sessions that need a second key wait for KeyClerk's approval.
- **P-B, LDAP lease credential.** The system binds against the appliance's facade. Outside a lease no person knows
  a facade password; a lease sets a fresh one, readable only with the person's own passkey, and rotates it at the end.
  Service accounts are workloads rotated on a schedule; break-glass is escrowed under dual control.
- **P-C, web front.** A web application behind the bastion's HTTPS target.

The only path in is the wrapper (decision 0002): the model lists every allowed flow and its check refuses any route to
the legacy system that bypasses the bastion.

## Repository
- `model/` - components, flows, patterns, contracts and open decisions, as YAML; `tools/check_model.py` checks them.
- `docs/decisions/` - decision records; `docs/prior-art.md` - what exists and what ReliKey adds.
- `agent/` - the edge agent (Go): applies signed leases, decides nothing; `build.py` runs the full gate.
- `deploy/core/` - the shared core as one composed pod (Caddy in front, Keycloak, KeyClerk, zot); `install.py` stands
  it up.
- `tests/` - model tests and the contract conformance set.

## Status
Early. The edge agent is built and heavily tested (conformance vectors, mutation, fuzzing); the core composition
stands up on rootless podman and on rootful docker. Full-stack lab runs on one box have proven passkey sign-in at the
broker, an edge enrolled with the officer's and the edge's signatures, a lease applied on Warpgate, a recorded session,
a revoke that cuts a held session, Warpgate's admin interface unreachable on the published port, and signed fleet
reports over post-quantum hybrid TLS. The fleet's enrolment by code and its officer anchor ceremony are built and
tested, not yet walked on a deployed box. The decision records and model are the design of record. What is **not**
done: production networking, high availability, signed releases, and several contracts still marked `needed` in the
model. Not production-ready; treat it as a working architecture you can stand up in a lab. What comes next is in
[ROADMAP.md](ROADMAP.md).

## Try it: the demo
With Go installed, `cd agent && go run ./cmd/relikey-demo` runs the real edge agent against stand-ins for KeyClerk,
Warpgate and the identity broker and shows, on a local page, a lease applied, a session, a revoke and a lease that
ends while the edge is offline. Keys are generated per run and nothing is left behind: [docs/demo.md](docs/demo.md).

## Quickstart: a lab on one box
A core and one edge on the same Linux host, the way full-stack run 2 stood them up (`docs/reviews/`). You need Python
3.11+, podman or docker with compose, a clone of KeyClerk beside this repository (with its signed release tags), and three names for the core plus one
for the edge that resolve to the host (in `/etc/hosts` for a lab). Run as a normal user; with docker, a member of the
docker group. `--lab` puts both pods on the host network: never in production.

1. **The core.** It prints the desk's bundle key and the front's certificate pin (or its CA) for the edge:

       git clone https://github.com/keyclerk/keyclerk ../keyclerk   # the installer builds the pinned release from its signed tag
       python deploy/core/install.py --broker-host id.lab --desk-host desk.lab --edge-host edge.lab \
           --root "First Last <root@example>" --officer "First Last <officer@example>" \
           --keyclerk-src ../keyclerk --engine docker --lab

2. **The first people.** The root holder and the officer sign in at the desk (`https://desk.lab:8443`) with the
   temporary passwords in `deploy/secrets/people.json`, set their own and register a passkey; then delete that file.
3. **Register the edge at the broker** (on the core): `python deploy/core/add_edge.py --edge plant-a --warpgate-url
   https://plant-a.lab:8888`.
4. **The edge.** It prints the edge's enrolment key, and the compose command to start it:

       python deploy/edge/install.py --edge plant-a --desk https://edge.lab:8443 --desk-ca deploy/secrets/front-ca.crt \
           --bundle-key <from step 1> --officer-key <the officer's key> --engine docker --lab \
           --sso-issuer https://id.lab:8443/realms/relikey --sso-secret-file deploy/secrets/warpgate-plant-a.secret \
           --sso-ca deploy/secrets/front-ca.crt --warpgate-url https://plant-a.lab:8888
       docker compose -f deploy/edge/compose.yaml -f deploy/edge/compose.lab.yaml up -d
       python deploy/edge/targets.py deploy/edge/targets.yaml      # the roles leases name, the targets, their host keys

5. **Enrol the edge at the desk.** The edge officer and the edge both sign the enrolment statement (the agent's
   `statement` and `cosign` commands, `docs/agent.md`); root proposes the enrolment and the officer approves it, each
   with a passkey. The officer then seals and sets the edge's ceiling.
6. **Grant and use.** Root grants a person a membership carrying a target's role; within a minute the agent applies
   the lease on Warpgate, and the person signs in to Warpgate through the broker and opens a recorded session.
   Ending the membership closes their sessions and removes the account.

Detail: `deploy/core/README.md` (the core, after-install steps, adding edges), `docs/agent.md` (the agent and its
enrolment CLI), `docs/installation-checklist.md` (what a real installation must establish). Once a lease is on the
edge, nothing needs the core or the cloud to keep it in force until it ends.

## Security
ReliKey is security infrastructure; treat findings responsibly. Report a weakness privately (see `SECURITY.md`), not
in a public issue. The design's own threat work and residual risks live with the maintainer, not in this repository.

## AI use
ReliKey is human-designed and AI-coded: the architecture, decisions and review are the maintainer's; an AI assistant
writes code and prose under that direction. Contributions declare their own level (`CONTRIBUTING.md`).

## Licence
EUPL-1.2. The composed components keep their own licences (NOTICE).

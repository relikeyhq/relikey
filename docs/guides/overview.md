# Operator overview: what runs where

For people who run ReliKey at a site. It says what the pieces are, where they run, what they keep on disk and how the
whole behaves when a part is down. The task guides build on it: [install](install.md), [operations](operations.md),
[troubleshooting](troubleshooting.md). The design and its reasons are in [architecture](../architecture.md) and the
[decisions](../decisions/README.md); if this page and the model in `model/` disagree, the model wins.

ReliKey is early: the README's Status section says what is proven and what is not (no high availability, no production
networking guide). Read it before you plan a site.

## Two tiers
- **The core**, once per organisation or site, on normal compute: the identity broker (Keycloak), KeyClerk (decides who
  may reach what, signs the result), the fleet service and an update mirror, behind one TLS front.
- **An edge**, one per encapsulated system, next to it: the bastion (Warpgate), the LDAP facade (lldap), a small TLS
  front and the edge agent. The agent applies what KeyClerk signed and decides nothing.

Nothing in the core opens a connection to an edge. Every connection runs from the edge out to the core's edge-facing
name, so an edge needs outbound HTTPS only.

## What the core runs
One pod, started with compose (`deploy/core/compose.yaml`, project `relikey-core`). Only the front is published.

| Service | What it does | Listens on |
|---|---|---|
| `front` | Caddy: TLS, routing by host name | 443 (8443 inside the pod; host loopback 8444 for the broker's admin console) |
| `broker` | Keycloak: sign-in, passkeys | loopback 8080, management 9000 |
| `broker-db` | PostgreSQL, the broker's database | loopback 5432 |
| `signer` | KeyClerk's checking signer, the only holder of the records key | a unix socket |
| `desk` | KeyClerk's desk and API: people, approvals, signed edge bundles | loopback 8091 |
| `reconcile` | KeyClerk's reconciler, the one writer of the broker's managed groups | none |
| `mirror` | update mirror edges pull from | loopback 5000 |
| `fleet` | ReliKey's fleet service: inventory, enrolment by code, the fleet page | loopback 8093 (page 8094) |

The front serves three names, each with only its own surface: the **broker's name** (sign-in, for people and for the
edges' Warpgate), the **desk's name** (the desk, for people) and the **edge-facing name** (the desk's edge routes, the
mirror's read API, the fleet's report and enrolment routes). A fourth name, the fleet page's, is optional. Details:
[the core's README](../../deploy/core/README.md).

## What an edge runs
One pod (`deploy/edge/compose.yaml`, project `relikey-edge`), all members in one network namespace.

| Service | What it does | Reachable on |
|---|---|---|
| `warpgate` | the bastion: SSH, web sign-in and web sessions, recorded | published 2222 (SSH) and, through the front, 8888 |
| `front` | Caddy: the published HTTPS port; refuses Warpgate's admin and self-service credential paths | 8888 |
| `facade` | lldap, the LDAP facade for systems that only bind to LDAP | loopback (LDAP 3890, admin 17170) |
| `agent` | `relikey-agent`: verifies bundles, makes Warpgate hold exactly the live leases | connects out only |

Warpgate's admin API listens on the pod's loopback (127.0.0.1:8899) and only the agent reaches it. The edge's status
page is a file the agent writes; the agent serves nothing.

## What happens in normal use
1. Root grants a person a membership that carries a target's role at the desk.
2. KeyClerk signs the lease into the edge's next bundle. The agent pulls bundles by long-poll, so a grant or a revoke
   arrives in seconds (it falls back to a pull every 60 seconds).
3. The agent verifies the bundle against the keys pinned on the edge and applies it: an account on Warpgate with the
   role, an SSO credential bound to the person's e-mail, and an expiry.
4. The person signs in to Warpgate through the broker (with a passkey) and opens a recorded session.
5. When the lease ends or is revoked, the agent closes the session and removes the account. Each tick (15 seconds) the
   agent recomputes what is live from the stored bundle and the trusted time, so leases end on time without anyone to
   ask.

## When something is down
- **The edge is down:** the system behind it is unreachable. That is deliberate (fail closed).
- **The core, or the network to it, is down:** leases already verified run until they end, up to the bundle's horizon.
  New sign-ins and new grants wait. The agent logs `pull failed` and keeps what it holds.
- **The agent is down:** Warpgate itself ends a session when the role that admitted it is revoked and expires grants at
  their `expires_at`, but nothing new is applied. Alert on a silent agent (see
  [operations](operations.md#watch-it)).
- **A bundle fails verification:** the edge keeps what it holds and counts a refusal (`bundles_refused`). It never
  applies a bundle it cannot verify.

## The keys and who holds them
| Key | Where it lives | What it does |
|---|---|---|
| Enrolment key | the edge: `deploy/secrets/enrolment.key`, in the pod `/etc/relikey/enrolment.key` | signs the edge's requests to the desk and its reports to the fleet; its public half is enrolled at the desk |
| Bundle key | pinned in the edge's `agent.json` (`pins.bundle_key`); the desk holds the private half | signs the edge's bundles |
| Edge officer's key | pinned in `agent.json` (`pins.officer_key`); the officer holds the private half | seals the edge's ceiling: the most a lease on this edge may grant |
| Desk certificate | the edge's `agent.json` (`clerk.ca_file` or `clerk.pin_sha256`) | the edge checks the desk's TLS by one of these |
| Bastion certificate | `bastion.pin_sha256` in `agent.json`, and `deploy/secrets/warpgate.pin` | the agent sends Warpgate's admin token only to the Warpgate with this certificate |
| Records key | the core's `deploy/secrets/records.key`, used by `signer` only | signs the desk's records |

The edge officer is a person, not a core administrator, and holds the officer key on their own device; the core cannot
widen an edge's ceiling. The people the core's installer seeds are the root holder, the security officer and, for an
edge, its officer (`--root`, `--officer`, `--edge-officer`).

## Where the state is
| Place | What | Matters because |
|---|---|---|
| core: `deploy/secrets/` | every secret and setting the installer wrote: `core.env`, the front's certificate and key, the records key, the broker's database password, `fleet/` | the installer keeps what it finds there; losing it cuts the core off its own data |
| core: named volumes `relikey-core_*` | `broker-db`, `broker`, `signer`, `desk`, `reconcile`, `mirror`, `fleet`, `front-data`, `front-config` | the people, records, inventory and evidence |
| edge: `deploy/secrets/` | `agent.json`, `enrolment.key`, `warpgate.token`, `warpgate.pin`, `governed-roles.json`, Warpgate's and lldap's environment files, the front's certificate files | the edge's identity and settings |
| edge: named volumes `relikey-edge_*` | `warpgate` (its configuration and certificate), `facade`, `agent` | the agent's volume holds the replay floors and the verified bundle |

`deploy/secrets/` is git-ignored: never commit it.

## Seeing what the edge thinks
The agent writes `status.json`, `status.html` and `metrics.prom` to its state directory (`/var/lib/relikey` in the pod)
and logs one JSON line per event on standard output. The canary gate is `relikey-agent status`, which exits 1 when
unhealthy. The [agent page](../agent.md) has the metrics and the alert rules; [troubleshooting](troubleshooting.md)
reads the messages.

## Where to go next
- [Install ReliKey at a site](install.md)
- [Run it: upgrade, back up, rotate](operations.md)
- [Troubleshoot from the messages](troubleshooting.md)
- Before an edge goes live: the [installation checklist](../installation-checklist.md)

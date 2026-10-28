# The ReliKey core (decision 0015: one pod)

The core is one pod of pinned upstream images plus KeyClerk, built from its tag:

| Service | What | Listens on |
|---|---|---|
| `front` | Caddy 2.11.7: TLS, routing by host name; the only published ports | 443 (in the pod: 8443), host loopback 8444 |
| `broker` | Keycloak 26.8.1, the broker (sign-in, passkeys, SCIM) | loopback 8080, management 9000 |
| `broker-db` | PostgreSQL 16.8, the broker's database | loopback 5432 |
| `signer` | KeyClerk's checking signer: the only holder of the records key | a unix socket only the desk mounts |
| `desk` | KeyClerk's desk and API: people, approvals, signed edge bundles | loopback 8091 |
| `reconcile` | KeyClerk's reconciler: the one writer of the broker's managed groups | (nothing; it calls the broker) |
| `mirror` | zot v2.1.22, the update mirror edges pull from (C-11) | loopback 5000 |

The front serves three names, each with only its own surface:
- the broker's name: the realm's sign-in, OIDC endpoints and keys, and the resources its pages load. Not the master
  realm, the admin console or the admin API. People and Warpgate on the edges (its OIDC issuer) use it;
- the desk's name: the desk and its API, for people;
- the edge-facing name: the desk's edge routes (`/api/v1/edge/*`, `/api/v1/edge-key`) and the mirror's read API
  (GET and HEAD under `/v2/`). Nothing else answers there.

The broker's admin console is on `https://localhost:8444` on the core host only: `ssh -L 8444:127.0.0.1:8444 core`.
Nothing in the core opens a connection to an edge (decision 0005).

## Install

    git clone https://github.com/keyclerk/keyclerk ../keyclerk   # install.py builds v0.26.3 from it with KeyClerk's Containerfile
    python deploy/core/install.py --broker-host id.example --desk-host desk.example --edge-host edge.example \
        --root "First Last <root@example>" --officer "First Last <officer@example>" --keyclerk-src ../keyclerk \
        [--cert front.crt --key front.key] [--engine podman|docker]

install.py:
1. writes `deploy/secrets/` (git-ignored; 0600; the files KeyClerk reads owned by its uid 10001), keeping every
   secret it finds there, so it can run again: `core.env` (the names and URLs compose reads), the database password,
   the broker's bootstrap admin, KeyClerk's writer and reader client secrets, the records key (and its public half),
   the first people and the desk's first records (a root holder appointed by an officer, nothing granted);
2. without `--cert`/`--key`, makes a local CA (`front-ca.crt`) and a leaf for the three names and `localhost`
   (`front.crt` holds the leaf followed by the CA, so the front presents the CA that enrolment codes pin);
3. builds `localhost/keyclerk:0.26.3` from the tag, starts the front, the database and the broker, and sets up the
   realm with `realm.py`. That sets SCIM on, e-mail editable by admins only, an admin-only `anchor` attribute behind
   SCIM `externalId`, the writer (group membership only, fine-grained permissions) and the reader, the desk's public
   PKCE client with the anchor in its tokens and back-channel logout, a client policy for every client (PKCE, no
   implicit or password grant), brute-force protection, events, 5-minute access tokens, and the two people with
   temporary passwords and a passkey to register;
4. starts the signer, the desk and the mirror; runs the reconciler once as a **dry run** and shows its plan; starts
   the reconciler only when you confirm (`--yes` skips the question);
5. prints what an edge's install.py needs: the desk's bundle key and the front's certificate pin (or the CA).

Then compose runs the core as usual:

    podman compose --env-file deploy/secrets/core.env -f deploy/core/compose.yaml ps

## After install
- The root holder and the officer sign in at the desk with the temporary passwords in `deploy/secrets/people.json`,
  set their own, and register a passkey. Then delete that file.
- Make a permanent admin for the broker in the master realm, with a passkey, and remove the bootstrap admin
  (`bootstrap-admin`). Then empty `deploy/secrets/broker-admin.env`: Keycloak reads it only to create an admin when
  the master realm has none. Do it soon: the bootstrap admin is a password-only admin over every realm, and its token
  endpoint answers anything on the pod's loopback.
- After that, adding an edge (`add_edge.py`), a vendor (`realm.py vendor`) or the fleet page (`fleet_page.py --host`)
  acts as the realm's own setup client `relikey-setup` (clients and identity providers in this realm only; secret in
  `deploy/secrets/relikey-setup.secret`). Changing people or login flows (`fleet_page.py --grant`, `realm.py
  vendor-link`, `realm.py passkey`) is done by your permanent admin in the broker's admin console, through the SSH
  tunnel. A core installed before the setup client existed: run `realm.py setup-client` once, while the bootstrap
  admin is still there.
- Enrolment by code (docs/fleet.md): with `--fleet-host` the installer also writes fleet.json's `admin` section once
  (kept on later runs, so the fleet keeps its id) and the page's `enrol_url` (the edge-facing name) and `pin` (the CA
  that issued the front's certificate, sha256), and prints them. The named officers then register their passkeys and
  sign the anchor on the fleet page; after that an operator opens a slot there and carries its code to the edge. With
  `--cert`, the file must hold the certificate followed by its issuing CA, or enrolment stays off and the installer
  says so; fix the file and run `python deploy/core/fleet_page.py --host <name>` again. An edge whose Python is older
  than 3.13 cannot check a pinned CA: it needs 3.13 or later to enrol.
- The KeyClerk configuration is `deploy/core/keyclerk.yaml`, a starting point from KeyClerk's neutral configuration,
  valid against its schema. A deployment keeps its own in its own repository and sets `KEYCLERK_CONFIG=<path>` in
  `core.env`.

## An edge
An edge reaches two of the core's names: the broker's (Warpgate's OIDC issuer) and the edge-facing one (the agent's
desk URL and the mirror). Both must resolve and route from the edge.

On the core, register the edge's Warpgate with the broker (a confidential client `warpgate-<edge>` with PKCE and its
one return URL; the secret lands in `deploy/secrets/warpgate-<edge>.secret` and is never printed):

    python deploy/core/add_edge.py --edge plant-a --warpgate-url https://plant-a.example:8888

Carry that secret file (and, with the local CA, `front-ca.crt`) to the edge out of band; there:

    python deploy/edge/install.py --edge plant-a --desk https://edge.example --desk-pin <pin> \
        --bundle-key <bundle key> --officer-key <the officer's key, from the officer's own console> \
        --sso-issuer https://id.example/realms/relikey --sso-secret-file warpgate-plant-a.secret [--sso-ca front-ca.crt]

Warpgate then signs people in at the broker for authentication only (decision 0010): it reads no roles claim, its
role_mappings hold one key no identity provider sends, and it creates no users; the agent provisions them from
signed leases. With `--sso-ca`, Warpgate trusts the core's CA through `SSL_CERT_FILE`, which names a bundle of the
public roots plus that CA (the variable is process-wide: recording upload and public targets keep working);
expected to work from Warpgate's build features, not yet proven on a box.

## A vendor's own sign-in (decision 0018, proposed)
A vendor's engineers can sign in with their company's OpenID provider instead of a password the plant manages. The
vendor registers a confidential client for the broker with the return URL
`https://<broker>/realms/<realm>/broker/<alias>/endpoint` and hands over its client id and secret. Inside the core pod:

    python realm.py vendor acme https://id.acme.example acme-client "Acme Maintenance" < secret
    python realm.py vendor-link vera.acme acme <Vera's subject at Acme's provider>

Only a linked identity gets in (an unlinked one is denied, never matched by e-mail or created), nothing is imported
from the vendor's provider, and the person's ReliKey passkey is still asked for after it (registered on the first
sign-in). What the person reaches is still their lease or visit lease. the lab harness (kept with the maintainer) checks all of this
against a local Keycloak.

## On podman
Every service shares the front's network namespace, and podman refuses to replace a container whose namespace others
use. Compose on podman can see a changed configuration between two identical calls and then try exactly that
(measured on podman 4.8). So install.py never recreates what runs (`run --no-deps`, `up --no-recreate`), and:
- a later `compose up -d` may fail with "has dependent containers": use `up -d --no-recreate`;
- to apply a changed configuration to a running service, recreate it on purpose: `compose up -d --force-recreate
  <service>` (not the front: the others hold its namespace), or `down` and `up` (the volumes stay unless you pass
  `-v`).

## Lab
`compose.lab.yaml` puts the pod on the host network, so the front answers on the host's 8443 and an edge pod on the
same box reaches it: `install.py --lab` (URLs then carry `:8443`), and the edge's `install.py --lab`, which puts
the edge pod on the host network too (`-f deploy/edge/compose.lab.yaml`). Never in production. On the host network the core's
loopback ports (5000, 5432, 8080, 8091, 9000) must be free on the host: another pod holding one of them (a second
KeyClerk desk on 8091, say) stops that service.

## Proven, 2026-10-24 (rootless podman 4.8, docker compose 5.6.1, the pod in its own namespace)
`install.py` end to end, with Keycloak's heap capped at 512 MB and the published port moved to 18443 (rootless podman
binds no port below 1024):

| Step | Result |
|---|---|
| KeyClerk 0.23.0 built from its tag with its own Containerfile | pass |
| Keycloak `start` on PostgreSQL, within realm.py's readiness wait | pass |
| realm.py: realm, profile, clients, policy, people; the writer's token opens SCIM | pass (SCIM 200) |
| the desk seeds its first records through the checking signer | pass (revision 1) |
| the reconciler's dry run on the fresh realm | pass (desired 0, add 0, remove 0, findings 0) |
| the desk's bundle key read; the front's pin over the published port equals the printed one | pass |
| the broker's name: the realm's OIDC discovery (issuer with the published port) | 200 |
| the broker's name: the master realm, the admin console, the admin API | 404 |
| the desk's name: the desk, its API contract | 200 |
| the edge-facing name: `/api/v1/edge-key`, the mirror's `GET /v2/` | 200 |
| the edge-facing name: `/`, `/api/v1/me`, the realm, a push to the mirror | 404 |
| the admin listener (host loopback): the admin console | 200 |
| `down` and `up` keeping the volumes: the desk's store and bundle key unchanged | pass |

The run found three faults, fixed in install.py: `run setup` re-converging its dependencies and `up` recreating
running services (both refused by podman, see above), and a local CA without key identifiers (refused by strict
verifiers such as Python 3.13). Not yet proven: docker, an edge signing in through the broker (the full-stack test),
Warpgate trusting the local CA, and memory figures (`podman stats` reads 0 B on this rootless setup; the honest
footprint is the soak on the reference hardware, R-10).

## Health and metrics (KeyClerk 0.24.0)

The desk answers `/healthz` (serving) and `/readyz` (store open and the reconciler within
`reconcile.ready_max_age_seconds`, default 900) on its own port, before the host check, so an orchestrator probes it
by address: the compose health check hits `/readyz`. With `--mgmt-port`/`--mgmt-token-file` (install.py writes the
token, >=32 chars) the desk also serves `/metrics` and a readiness detail on `127.0.0.1:8092` behind a bearer token,
published on the core host's loopback only (scrape over an SSH tunnel, like the admin console). Keycloak's own health
is already on its management port (`KC_HEALTH_ENABLED`). The evidence table above is the 0.23.0 stand-up; the 0.24.0
bump and this health/metrics wiring are config-validated but not yet re-stood-up (next full-stack run).

## Known residuals (decision 0015)
- The front holds the TLS key for the broker's name and the desk's: it is a trust boundary, in scope for the
  full-stack test and a later review. The records stay signed end to end, whatever the front does.
- Keycloak runs with a writable root (`start` builds into the image on first boot). Caddy and zot run as uid 0 (no
  unprivileged user in their images): zot with no capabilities, Caddy with NET_BIND_SERVICE only.
- The mirror listens on the pod's loopback only; filling it from a signed update manifest (C-11) is not built yet.
- Not yet: core HA (0012 HA-1, 0013), approval proofs on the signer (`--approval-issuer`), the console
  (`keyclerk.console`).

## Approval proofs on an existing core

`keyclerk.yaml` requires approval proofs (`approvals.proofs: required`, contract C-05): every approval is the approver's
own fresh sign-in at the broker, and the signer and the reconciler verify it (compose passes them the broker's issuer,
audience and keys). A core installed before this has approvals without a proof in its records, and the reconciler then
refuses every run, naming them. They are pinned, not re-done: list them with KeyClerk's
`python -m keyclerk.approvals pin <records>` (or compute `{record, by, sha256: approvals.record_hash(kind, record)}`),
review each, and put the ones that predate the policy under `approvals.accepted_without_proof` in the deployment's own
keyclerk.yaml. Never pin an approval that has a proof. Ending a record keeps its pin (the end is a separate revocation
record). Proven on the full-stack box, 2026-10-24: one pinned approval, and the reconciler applied again.

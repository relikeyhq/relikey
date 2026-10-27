# Warpgate internals: code structure and scaffolding

Read from upstream main `a2570d76` (2026-10-20, v0.30.0 line) while building and testing
[warp-tech/warpgate#2782](https://github.com/warp-tech/warpgate/pull/2782) (separate admin listener, our U-08).
Line counts are of `src/**/*.rs` per crate. Everything here was read in the source or observed on a running build; where
something is inferred it says so. This is the map ReliKey's edge agent, filtering proxy and upstream work rely on.

## 1. Workspace map

Rust workspace (`Cargo.toml` `[workspace]`), toolchain pinned in `rust-toolchain.toml` (nightly-2026-07-09), plus a
Svelte front end in `warpgate-web/`. About 112k lines of Rust in 27 crates.

| Crate | Lines | Role |
|---|---|---|
| `warpgate` | 2.9k | The binary: CLI (`commands/`), config loading and file watching (`config.rs`), listener supervision (`listener_supervisor.rs`), logging setup |
| `warpgate-core` | 16.7k | The engine: `Services`, sessions `State`, cluster, approvals, auth state store, config providers, recordings, login protection, rate limiting, listener status, secret backend registry, protocol trait |
| `warpgate-common` | 8.4k | Config types (`config/mod.rs`, defaults, `config_schema` bin), `ListenEndpoint`, errors, helpers (PROXY protocol, password policy), encryption, secrets types |
| `warpgate-common-http` | 1.8k | HTTP plumbing shared by HTTP-facing crates: request contexts and authorization types (`auth.rs`), cluster mTLS acceptor and peer marker (`cluster_tls.rs`), external URL construction (`ext.rs`), request logging and client IP (`logging.rs`), errors, internal pages; with #2782 also `listener.rs` |
| `warpgate-protocol-http` | 8.8k | The HTTP server: route tree, middleware, user API (`api/`), HTTP target proxy (`proxy`, `catchall`), sessions, CSRF and host checks (`common.rs`) |
| `warpgate-admin` | 8.4k | The admin API (`api/`, 35 modules) as a poem-openapi service, plus its OpenAPI-spec binary |
| `warpgate-protocol-ssh` | 8.5k | SSH bastion on russh (0.63.3): client auth, target connections, recording |
| `warpgate-protocol-rdp` | 4.3k | RDP (IronRDP), in-workspace integration |
| `warpgate-protocol-kubernetes` | 3.3k | Kubernetes API proxy, client certificates |
| `warpgate-protocol-vnc` | 2.0k | VNC |
| `warpgate-protocol-mysql` / `-postgres` | 1.3k each | Database protocol proxies |
| `warpgate-database-protocols` | 2.9k | Vendored protocol parts of SQLx |
| `warpgate-db-entities` | 3.6k | sea-orm entities (33 files) |
| `warpgate-db-migrations` | 8.9k | sea-orm migrations (94, `m00001`..`m00094`) |
| `warpgate-sso` | 2.0k | OIDC client side for SSO |
| `warpgate-ldap` | 0.6k | LDAP as a user directory (not a target) |
| `warpgate-tls`, `warpgate-ca` | 1.1k, 0.3k | TLS loading and helpers; the cluster CA and identities |
| `warpgate-secrets-vault` | 0.5k | Vault / OpenBao secret backend |
| `warpgate-aws` | 0.9k | AWS helpers (EC2 detection, S3) |
| `warpgate-web-ssh`, `warpgate-web-desktop`, `warpgate-web-clients-common` | 0.6k, 1.3k, 0.5k | Browser SSH and desktop clients over WebSocket |
| `warpgate-desktop-auth`, `warpgate-desktop-ui` | 0.7k, 0.4k | Viewer authentication and "connecting" screens for native RDP/VNC |
| `warpgate-web` | 37 | Embeds the built front end (`Assets`) with rust-embed |
| `warpgate-common-cache` | 0.2k | Small caching helpers |

Build profiles (`Cargo.toml`): `dev` with `debug = "line-tables-only"`; `release` with `lto = true` and stripped debug
info; `release-no-lto`; `coverage`. A debug build of the whole workspace took about 3 minutes on 8 dedicated vCPU and
32 GB; it did not finish in a 3 GB / 2 CPU WSL VM in 25 minutes. The debug binary is about 446 MB.

## 2. Process start-up and the listener model

`warpgate/src/main.rs` dispatches to `commands/`: `setup` (interactive) and `unattended-setup`, `run`, `check`,
`healthcheck`, `migrate`, `copy_database`, `create_user`, `recover_access`, `client_keys`, internal file installation.

`commands/run.rs` (`command`):
1. Loads the config (`load_config`), validates encryption settings (`validate_encryption_config`) and, with #2782,
   refuses an `http.admin` that overlaps `http.listen`.
2. Builds `Services` (`warpgate-core/src/services.rs`), backfills credential encryption (deferred if the cluster is not
   ready), prints the banner.
3. Starts `watch_config` (`warpgate/src/config.rs`): the config file is watched, debounced (500 ms of quiet), reloaded,
   written into `services.config` **first**, then pushed on a watch channel. So anything that reads
   `services.config` per request switches before listeners react.
4. Spawns one **supervisor per listener** (`listener_supervisor.rs`): HTTP (always on), SSH, MySQL, PostgreSQL,
   Kubernetes, VNC, RDP (a `tls_listener!` macro covers the uniform ones), and with #2782 "HTTP admin". Each supervisor
   gets a `ServerFactory` (builds and binds a `ProtocolServer`) and a `ConfigSelector` (maps the config to
   `ListenerParams { enabled, endpoint, proxy_protocol, tls }`). On every config push it compares the params and
   rebinds only on a change of endpoint, enable flag or certificates. A failed bind is not fatal: the listener pauses
   in `BindFailed` until the config or a certificate changes. Status goes to the `ListenerStatusRegistry` shown on the
   admin Network page (`warpgate-admin/src/api/network_status.rs`).
5. Background loops: DB cleanup by retention, session approval and ticket expiry sweeps, cluster liveness.

`ProtocolServer` (`warpgate-core/src/protocols/mod.rs`) has two phases: `bind(address, proxy_protocol, tls)` returns a
future after binding the socket; errors there pause the listener, errors from the returned accept-loop future restart
it. `ListenEndpoint` (`warpgate-common/src/types/listen_endpoint.rs`) binds `[::]` as two sockets (v6-only plus
`0.0.0.0`), uses `SO_REUSEADDR` (not on Windows), and `probe()`s by binding without listening. Consequence: two
supervisors can race for the same port; that is why #2782 makes an overlapping admin listener a hard error.

`Services` holds: `db` (sea-orm `DatabaseConnection`, SQLite or PostgreSQL), `recordings`, `config`
(`Arc<Mutex<WarpgateConfig>>`), `cluster`, `state` (live sessions), `config_provider` (users, targets, roles),
`auth_state_store` (in-flight logins), `admin_token`, `rate_limiter_registry`, `login_protection`, `global_params`,
`listener_status`, `secret_backends`.

## 3. Configuration

`WarpgateConfig { store: WarpgateConfigStore, paths_relative_to }`; the store has a section per protocol
(`http`, `ssh`, `mysql`, `postgres`, `kubernetes`, `vnc`, `rdp`), `log`, `recordings` and more. Config types derive
`Serialize`, `Deserialize` and `schemars::JsonSchema`. `config-schema.json` at the repository root is generated by
`cargo run -p warpgate-common --bin config-schema` (`just config-schema`) and **CI fails if it is stale**.

Many runtime settings are **not** in the file but in the database (`Parameters` entity), seeded at setup: recording on
or off, host key verification, password login mode, ticket and approval parameters. Tests set those at setup time,
not by patching the config file.

When a setting is read matters:
- read **per request**: `trust_x_forwarded_headers` in `get_client_ip`; with #2782 `http.admin` in the admin guard;
- read **at bind**: `UnauthenticatedRequestContext::new` captures trust for host and protocol checks; cookie and
  session ages; the cookie domain derived from `external_host`;
- applied **by rebind** through the supervisor: endpoints, enable flags, certificates.

`http` today: `listen`, `proxy_protocol`, `external_port`, `external_host`, `certificate`, `key`,
`trust_x_forwarded_headers`, `session_max_age`, `cookie_max_age`, `sni_certificates`; #2782 adds `admin`
(`listen`, `proxy_protocol`, `trust_x_forwarded_headers`, `external_port`).

## 4. The HTTP server

`warpgate-protocol-http/src/lib.rs`, `HTTPProtocolServer::bind`, builds one poem app per listener:

```
Route
 ├─ /@warpgate  -> at_warpgate_endpoints()
 ├─ /_warpgate  -> at_warpgate_endpoints()      (the same endpoints again; an alias)
 └─ /           -> page_auth(catchall)           (HTTP targets: the reverse proxy)
at_warpgate_endpoints():
   /api/playground, /api (user API, poem-openapi), /api/openapi.json
   /assets (embedded front end), /api/logo
   /admin/api   -> endpoint_auth(admin_api_app)  (warpgate-admin)
   /admin       -> the admin SPA shell (CSP with the S3 recordings origin)
   /api/auth/web-auth-requests/stream, /api/web-ssh/sessions/:id/stream,
   /api/web-desktop/sessions/:id/stream          (WebSockets, forwarded to the owning node)
   ""           -> the gateway SPA shell
   around: request logging (method, URL, status, client IP); SecurityHeadersMiddleware
```

Middleware, outermost first on the app: `render_errors`, `.data(...)` (request contexts, HTTP client cache, session
store and storage), `cluster_peer_extension`, `CookieHostMiddleware`, `ServerSession` (cookie sessions), 
`TicketMiddleware`, HSTS header, span and session processing, `inject_request_authorization`. The acceptor stack is
`ListenEndpoint::poem_acceptor` -> `MaybeProxyProtocolAcceptor` -> `cluster_aware_tls_acceptor` (public certificates
by SNI plus the cluster identity under its own SNI with mandatory client auth).

**Both prefixes matter.** Anything that filters Warpgate paths (a reverse proxy, our edge filtering proxy) must treat
`/@warpgate` and `/_warpgate` alike. Poem matches raw paths: encoded (`%40warpgate`, `%61dmin`), doubled-slash and
case variants do not reach the admin routes (tested in #2782).

**Request authorization** (`warpgate-common-http/src/auth.rs`): `RequestAuthorization` is `Session(User | Ticket ...)`,
`UserToken`, or `AdminToken` (the `WARPGATE_ADMIN_TOKEN` with `run --enable-admin-token`). Admin API permissions are
scoped and granted through admin roles (`AdminPermission`: `TargetsCreate`, `TargetsEdit`, `TargetsDelete`,
`UsersCreate`, `UsersEdit`, `UsersDelete`, `AccessRolesCreate`, `AccessRolesEdit`, `AccessRolesDelete`,
`AccessRolesAssign`, `SessionsView`, `SessionsTerminate`, `ApproveSessions`, `RecordingsView`, `TicketsCreate`,
`TicketsDelete`, `ConfigEdit`, `AdminRolesManage`, `TicketRequestsManage`), checked per endpoint with `admin.require(...)`. A third scheme, `ClusterPeerAuth`,
admits peer-forwarded admin requests on endpoints that are legitimately cross-node.

**CSRF and host binding** (`warpgate-protocol-http/src/common.rs`): the session cookie is `SameSite=None` and shared
with target subdomains, so for state-changing and WebSocket requests to Warpgate's own surface
`is_cross_origin_api_request` refuses to count the cookie when `Sec-Fetch-Site` is `cross-site` or `same-site`, or
when the `Origin`/`Referer` host differs. The host comparison ignores the port by design (proxies rewrite ports); #2782
adds a port comparison on the admin listener only. Sessions are bound to the base host or its subdomains or localhost
(`session_host_is_authorized`); on `/@warpgate` paths a session from a non-control-plane host is restricted. A second
listener must therefore be addressed by `external_host` (any port).

**Client IP** (`warpgate-common-http/src/logging.rs`): `get_client_ip` uses `X-Forwarded-For` only when trusted;
login protection blocks by that IP. Behind a load balancer without PROXY protocol every client shares one IP.

## 5. Cluster

Nodes share one database. Each node has a TLS identity from the cluster CA (`warpgate-ca`); peers authenticate with
mutual TLS, pinned by SPKI hash (`cluster_tls.rs`: `node_for_pin`), and the acceptor annotates the remote address;
`cluster_peer_extension` turns that into a `ClusterPeer` request extension. Headers and PROXY protocol cannot set it.

A node advertises `ip:http.listen.port` (`Cluster::new`, `advertised_peer_address`). Cross-node calls go to the
peer's **main HTTP port** under the admin API: `post_to_peer` sends `POST /@warpgate/admin/api{route}` for
`/cluster/notifications` (session changes, approval changes, web auth requests) and `/cluster/close-sessions`
(close-all, close one, delete user). WebSocket streams for web SSH and desktop are forwarded to the session's owning
node (`forward_ws_to_session_owner`). Any change that restricts the admin API on the main port must keep answering
cluster peers; #2782 does, and its peer test fails if that exemption is removed.

## 6. Access, approvals, credentials, evidence

- **Roles and expiring assignments**: `/users/:id/roles` and `/users/:id/roles/:role_id` with `expires_at`
  (`null` = permanent); an assignment is active when not expired and not revoked; `AccessRolesAssign`.
- **Session approvals (JIT, since 0.29)**: targets can require an admin to approve each session; `GET /session-approvals`,
  `POST /session-approvals/:id/approve|reject`, a changes stream; `ApproveSessions`; approval caching and timeouts;
  cross-node via cluster notifications.
- **Ticket requests**: users request tickets, admins approve (`ticket_requests_*`).
- **User credentials**: password, OTP, public key (`credentials_public_key.openssh_public_key`; `UsersEdit`), SSO,
  certificate credentials (Kubernetes). FIDO `sk-*` keys are not accepted by russh 0.63 (russh #760).
- **Target credentials**: stored, or fetched from a Vault/OpenBao backend; SSH targets can use per-connection
  certificates signed by Vault/OpenBao (0.30).
- **Recordings**: every session, live view and replay; on local disk or S3 (presigned URLs, hence the admin CSP).
- **LDAP**: a user directory (`warpgate-ldap`, `/ldap-servers`, user-LDAP links), never a protocol target.

## 7. Front end

`warpgate-web/` is Svelte 5 with Bootstrap, built by Vite into assets embedded by `warpgate-web` (rust-embed). Two
apps: `src/admin/` (the admin SPA at `/@warpgate/admin`) and `src/gateway/` (the user portal at `/@warpgate`), plus
`src/common/`. API clients are generated, not hand-written: `npm run openapi:schema:gateway` runs
`cargo run -p warpgate-protocol-http` (the crate prints its OpenAPI spec) into `src/gateway/lib/openapi-schema.json`
(committed), and `openapi:client:*` runs `openapi-generator-cli` (a Java program: **Java must be installed**, or
`npm ci` fails in its prepare step) into `lib/api-client` (generated at build). Lint is `npm run lint` =
`biome ci && svelte-check`; one pre-existing biome finding exists in `src/admin/config/AccessRole.svelte` on main.
The portal links into the admin SPA in several places (Admin button, target edit, getting started, API playground) and
`common/RequestsButton.svelte` polls `/@warpgate/admin/api` every 30 s plus a WebSocket for approval counts.

## 8. Tests and CI

**E2E** (`tests/`, 74 `test_*.py` files): pytest with xdist (`-n 4`), poetry-managed (`pyproject.toml`; the
`dev-dependencies` section is deprecated but works). `conftest.py`'s `ProcessManager.start_wg(config_patch=...,
share_with=..., http_port=...)` runs `unattended-setup` then `run --enable-admin-token` with
`WARPGATE_ADMIN_TOKEN=token-value` and `WARPGATE_UNDER_TEST=1`; `share_with` starts a second node on the same database
for cluster tests; `config_patch` is deep-merged into the YAML after setup; `log_path` holds the node's output.
`shared_wg` is a session-wide node; `admin_client(url)` gives the generated Python SDK (`openapi_client`, produced by
`npm run openapi:tests-sdk` into `tests/api_sdk`, required before the suite imports). Targets run in Docker images
built by `tests/Makefile` (`image-ssh-server`, `-mysql-`, `-mariadb-`, `-postgres-`, `-vnc-`, `-rdp-`). Without
`ENABLE_COVERAGE=1` the suite runs `target/debug/warpgate`; `tests/run.sh` is the coverage run with cargo-llvm-cov.
The request log line format (`status=...`, "Request" vs "Request failed") is usable to assert that a request was
served rather than refused.

**CI** (`.github/workflows/`): `build.yml` (also fails on a stale `config-schema.json`), `test.yml`, `clippy.yml`,
`biome.yml`, `fmt-toml.yml`, `cargo-deny.yml`, `lockfile.yml`, `reprotest.yml`, `codeql.yml`, `scorecard.yml`,
`docker.yml`, `helm-publish.yaml`, `check-schema-compatibility.yml` (oasdiff against main for the admin and gateway
APIs, fails on breaking changes), and `ai-comment-check.yml`: every issue or PR comment between 200 and 20,000
characters is judged by an AI model (`actions/ai-inference`, `openai/gpt-4.1`), presumably for AI-generated filler.
Keep our comments short and specific. Workflows on a first-time contributor's PR wait for the maintainer's approval.

**Packaging**: `docker/` (Dockerfile, compose, local testing), `helm/warpgate` (chart, `e2e.sh`), a Terraform provider
and a Kubernetes operator outside this repository.

## 9. Contributing

Policy (README): AI-assisted contributions are accepted with disclosure; the PR template has an "AI Usage" section with
four levels (ours: "Human-designed, AI-coded"). No CONTRIBUTING file, CLA or DCO. Tasks via `just` (`run`, `fmt`,
`clippy`, `test`, `npm`, `lint`, `openapi-all`, `config-schema`). Formatting with `cargo fmt --all` also touches files
upstream left unformatted (`m00093_log_session_id_nullable.rs` on main): restore anything the change did not touch.

## 10. What this means for ReliKey

- The edge agent drives Warpgate only through the admin API with a scoped admin role: `AccessRolesAssign` (lease ->
  role with `expires_at`), `ApproveSessions` (approvals from signed leases), `UsersEdit` (visit keys; this makes the
  agent effectively a full admin, decision 0007), `SessionsTerminate` (end sessions with the lease, decision 0008).
- Until #2782 lands, the edge filtering proxy must refuse the admin UI and API under both `/@warpgate` and
  `/_warpgate`, after decoding and normalising (decision 0008). With #2782 the edge sets `http.admin.listen` to
  loopback and the proxy can go.
- In a Warpgate cluster the agent must never block admin calls between nodes on the main port.
- Offline sign-in uses plain `ssh-ed25519` keys until russh accepts `sk-*` keys (U-01).
- Recordings go to the organisation's S3-compatible store; Warpgate's own S3 support covers it.

## Changelog
- 2026-10-23: written from the source and the #2782 build and test runs on an 8-vCPU Linux build host.

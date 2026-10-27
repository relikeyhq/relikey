# Component facts

What the model and the decisions assume about each component, checked against the source on 2026-10-23. Each fact
says how it was checked. A decision that rests on an unchecked or refuted fact is not accepted.

## Warpgate (v0.30.0, Apache-2.0)
| Fact | Result | How checked |
|---|---|---|
| Targets SSH, HTTPS, Kubernetes, MySQL, PostgreSQL, RDP, VNC | confirmed | README; crates `warpgate-protocol-{ssh,http,kubernetes,mysql,postgres,rdp,vnc}` |
| Session approvals over the admin API | confirmed | `warpgate-admin/src/api/session_approvals.rs`: `GET /session-approvals`, `POST .../:id/approve`, `POST .../:id/reject`, a stream; permission `ApproveSessions` |
| Role assignments with expiry | confirmed | `warpgate-admin/src/api/users.rs`: `expires_at` ("null = permanent"), active = not expired and not revoked, `/users/:id/roles[/:role_id]` |
| Admin UI and API on the user listener, under both `/@warpgate/admin` and `/_warpgate/admin` | confirmed | `warpgate-protocol-http/src/lib.rs` nests the same endpoints at `/@warpgate` and `/_warpgate` (main, 2026-10-20) |
| Admin UI and API behind a separate listener | proposed upstream | warp-tech/warpgate#2782 (U-08); internals in docs/warpgate-internals.md |
| Cluster peers call each other's admin API on the user HTTP port | confirmed | `warpgate-core/src/cluster.rs` `post_to_peer` -> `/@warpgate/admin/api{route}` over cluster mutual TLS |
| LDAP as a user source, not a target | confirmed | `warpgate-ldap`, `ldap_servers.rs`, user-LDAP link migrations; issue #35 asks for user sync only |
| Users can hold an OpenSSH public key credential | confirmed | `warpgate-db-entities/src/PublicKeyCredential.rs` (`openssh_public_key`) |
| FIDO SSH keys (`sk-ssh-ed25519`, `sk-ecdsa`) accepted for user sign-in | **refuted** | Warpgate uses russh 0.63.3 (`Cargo.toml`); russh issue #760 (open since 2026-08-28): server-sig-algs advertise only `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`, `ssh-rsa` |
| ECDSA user keys | refuted (same list) | russh #760 |
| SSH certificate sign-in for users | absent | issues #26 (since 2022), #1741 open; PR #1847 (open) covers certificates toward targets only |
| Vault/OpenBao secret backend; per-connection SSH certificates toward targets | confirmed | v0.30.0 release notes (#2185, #2734) |
| HA clustering, recordings on object storage | confirmed | v0.27.0 release notes |
| Binaries | arm64 and x86_64 Linux, 102 MB and 109 MB, glibc-linked (built on Ubuntu 22.04), web UI inside; image `distroless/cc-debian12` | release assets of v0.30.0; `.github/workflows/build.yml`, `docker/Dockerfile` |
| Recording upload to S3 retries | **absent**: a failed write is logged and dropped | `warpgate-core/src/recordings/storage.rs` |
| Container image | 49 MB compressed, arm64 and amd64, no armv7 | registry manifest of `ghcr.io/warp-tech/warpgate:latest` |
| Memory at idle and under sessions | 48 MB idle, 54 MB at 1, 67 MB at 10, 85 MB at 25 terminal sessions (release, amd64); not returned after sessions | docs/measurements.md (2026-10-23 soak) |
| AI-assisted contributions | accepted with disclosure | README; PR template "AI Usage" |

## LDAP facade candidates
| Fact | lldap v0.6.3 (GPL-3.0) | glauth v2.5.4 (MIT) | How checked |
|---|---|---|---|
| Image, compressed | 26-28 MB, amd64, arm64, arm/v7 | 24-25 MB, amd64, arm64, arm/v7, riscv64 | registry manifests |
| LDAP Password Modify extended operation (RFC 3062), so the agent can rotate a password over LDAPS | **yes** | not found | lldap `crates/ldap/src/password.rs` (`LdapPasswordModifyRequest`, `do_password_modification`); no match in glauth code search |
| Backends | own database (SQLite or others), web UI | config file, chained plugin backends | READMEs |

Consequence for R-02: lldap fits contract C-03 as written; glauth would need its config or a database backend
rewritten by the agent.

## Keycloak and OpenBao (core)
| Fact | Result | How checked |
|---|---|---|
| Keycloak 26.8.1 image | 265 MB compressed; amd64, arm64, ppc64le | registry manifest |
| OpenBao 2.7.1 image | 75-80 MB compressed; amd64, arm64, arm/v6, ppc64le, riscv64, s390x | registry manifest |
| OpenBao LDAP engine: static-role rotation, dynamic users, service-account check-out | confirmed | `website/content/docs/secrets/ldap.mdx` |

## KeyClerk
Version 0.15.0; its image is in a private registry and was not inspected here. Decisions 0006 (approvals as signatures),
0011a (planes) and 0013 (topologies, signed bundles D3) are the ones ReliKey depends on.

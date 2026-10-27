# Prior art

Sweep of 2026-10-23: GitHub metadata of 53 repositories, topic searches (pam, bastion, privileged-access-management,
identity-aware-proxy, ldap-proxy, jit-access, session-recording, and more), README and release-note reading, and code
reading of the APIs ReliKey relies on. Facts are as of that date.

## Conclusion
No open project packages an identity broker, a bastion and governance as code as one small appliance in front of
legacy systems, and none lets an LDAP-only system's own bind be satisfied after a passkey sign-in under an approved,
time-limited lease. The one complete implementation of that LDAP pattern is commercial (Strata Maverics LDAP
Provider: an identity-aware proxy signs the user in at the IdP, then the application binds with a one-time credential).

## Closest open work
| Project | What it covers | What it lacks for ReliKey |
|---|---|---|
| Warpgate 0.30 (Apache-2.0) | Bastion for SSH, HTTPS, Kubernetes, MySQL, PostgreSQL, RDP, VNC; OIDC and TOTP; recording; HA (0.27); session approvals (0.29) and expiring role assignments via admin API; Vault/OpenBao secret backend (0.30) | Passkeys of its own, LDAP-bind facade, leases, policy, signed approvals |
| authentik (MIT core) | IdP with LDAP provider; LDAP bind with an expiring app password created after a web sign-in; TOTP appended to the password | Approval and lease around the app password; it is itself the IdP |
| privacyidea-ldap-proxy (AGPL-3.0) | Intercepts LDAP binds, checks PIN+OTP | OIDC, passkeys, leases |
| OpenBao LDAP engine (MPL-2.0) | Static-role rotation, dynamic users, service-account check-out | Is a building block; no person-facing flow |
| Teleport (AGPL-3.0 source) | Full access platform: SSO, passkeys, access requests, recording, DB, Kubernetes, desktops | Not small; no LDAP-bind facade; binaries under separate terms |
| JumpServer (GPL-3.0), Next Terminal, OneTerm, Casvisor | Bastions with RDP/VNC/SSH and recording | Governance as code, LDAP facade |
| custodexa (AGPL-3.0, new 2026-08) | Bastion with per-asset direct / reason / approval with time-limited authorization | Very young; no LDAP facade |
| orion-belt (Apache-2.0 + Commons Clause) | SSH gateway with JIT approvals via API and ChatOps | SSH only; not open source by OSI terms |
| discord/access, jit-groups | Time-limited group access with approvals | Not tied to a bastion or legacy credentials |

HashiCorp Boundary's community edition was archived on 2026-10-08.

## Second sweep (2026-10-23): OT remote access, offline access, consoles
Topic searches ot-security, ics-security, industrial-security, secure-remote-access, remote-access-gateway,
console-server, serial-console, out-of-band-management, break-glass, ssh-certificates, ssh-ca, zero-trust-access,
iec-62443, plus keyword searches on OT, PLC and robot remote access, offline and break-glass access, temporary LDAP
passwords and edge bastions on small boards.
- **No open secure-remote-access product for OT/ICS was found.** The topics hold labs, scanners, pentest tools and
  reading lists (GRFICS, labshock, ICS-Security-Tools); the products in this space are commercial.
- **Short-lived SSH certificates** are well covered: Netflix BLESS (Apache-2.0), Cloud-Foundations keymaster
  (Apache-2.0, SSH and X.509 CA with OpenID Connect), obelisk/rustica (MIT, an SSH CA using a YubiKey), CURSE, certonid,
  smallstep. They issue certificates; none governs leases or works as an appliance with a bastion. Useful if Warpgate
  gains user certificates (docs/upstream.md U-02).
- **Machine identity for factories**: Trustpoint (MIT) manages device certificates in OT; adjacent, not access.
- **Break-glass**: only cloud-account patterns (awslabs/aws-break-glass-role) and small demos; nothing for an offline
  device.
- **Serial consoles**: terminal apps and hobby console servers; none behind a recorded, governed bastion.

Conclusion holds: ReliKey's offline visit leases, phoned unlock and break-glass for devices have no open equivalent.

## Commercial references: what to learn, what not to carry (2026-10-23)
Both are far too large for ReliKey's edge; both have patterns worth taking.

**Azure Bastion** (learn.microsoft.com/azure/bastion, read 2026-10-23)
- Targets need no public IP, agent or client software; RDP and SSH over TLS on 443. Same rule as ReliKey 0002.
- Native clients (the user's own SSH or RDP client) in Standard and Premium; Warpgate does the same.
- Shareable links with an expiry let users without directory accounts connect, but "The shareable link doesn't contain
  any credentials - the admin must provide sign-in credentials to the user": the credential travels out of band.
  ReliKey takes the expiring invitation, not the out-of-band password: a visitor gets a KeyClerk visit and lease.
- Session recording only in Premium, written to the customer's own blob storage (managed identity). Lesson: recording
  belongs in every tier and in the organisation's store, as in ReliKey 0005.
- Limitation to avoid: Entra ID sign-in for RDP in the portal cannot be combined with graphical session recording.
  ReliKey must keep sign-in and recording working together; that is a test, not a hope.
- Private-only deployment (no public IP) in Premium. ReliKey's edge never takes inbound traffic from the internet.
- The weight: a dedicated /26 subnet, managed VM instances as scale units, billed from deployment, and reachable only
  from an Azure virtual network. It cannot sit next to a robot.

**Idira (CyberArk, rebranded by Palo Alto Networks on 2026-05-12)** (docs.cyberark.com, read 2026-10-23)
- Dual control: a user states a reason and whether access is once or repeated; Safe owners confirm; "If more than one
  confirmation is required, each group is equivalent to a single authorized user". Lesson for KeyClerk's second key: a
  group of approvers counts once, and the request carries reason and scope.
- Exclusive check-out of a one-time password, locked against other users, released by time or at session end, then
  rotated by the CPM ("PSM can automatically unlock these exclusive accounts after a PSM session ends"). This is
  ReliKey's P-B, with two refinements to adopt: one holder per account at a time, and rotation at session end when
  that comes before the lease end.
- Session isolation: credentials injected by the session manager, never shown. ReliKey's P-A in front of P-B.
- Remote Access for vendors: invitations (ad hoc, by delegated vendor managers) give "just-in-time access to critical
  organizational applications", vendors authenticate with the Idira Mobile app "using built-in strong, biometric
  authentication". The pattern matches KeyClerk visits and ReliKey's outbound-only edge. Not verified here: the
  connector's network model and footprint.
- The weight: a vault, a password manager service, session manager servers (historically Windows), a web access tier
  and a cloud tenant. The opposite of an edge on a switch.

The full source log (every repository, search and page consulted) is kept with the operator's notes.

## Secure, self-healing fleets (verified 2026-10-25, for decision 0026)
| Project or source | What it shows | Use for ReliKey |
|---|---|---|
| Uptane standard (uptane/uptane-standard) | A director repository (per-device release choice) and an image repository, both on TUF; full verification on primaries, partial (director root and targets) on constrained secondaries | the release model (0026 point 7) |
| aktualizr (uptane/aktualizr, MPL-2.0) | the reference C++ Uptane client; last release 2020.2 (February 2020) | not used: dormant |
| go-tuf v2 (theupdateframework/go-tuf, Apache-2.0) | the TUF client workflow (root, timestamp, snapshot, targets): rollback, freeze and mix-and-match protection | the library for point 7 |
| RAUC (rauc/rauc, LGPL-2.1) | redundant slots, X.509/CMS-signed bundles, streaming and adaptive updates; the bootloader counts boots and falls back | OS rollback on appliances ReliKey images (point 8) |
| systemd-sysupdate and systemd-boot automatic boot assessment | A/B versioned updates; boot counting with fallback lives in systemd-boot, not in sysupdate | the alternative to RAUC where hosts boot with systemd-boot |
| Mender client (Apache-2.0) | A/B rootfs with automatic rollback, needing bootloader integration | prior art for point 8 |
| CISA/FBI on Kaseya VSA (July 2021); CISA ED 21-01 on SolarWinds Orion (2020) | ransomware and a compromised build delivered through IT management tooling | the read-only invariant (point 9) |
| Kubernetes version skew policy | the kubelet up to three minor versions older than the API server, never newer | the skew policy (point 11: two) |
| SLSA v1.2 | build levels L0 to L3; provenance as an in-toto attestation | the target for signed releases |


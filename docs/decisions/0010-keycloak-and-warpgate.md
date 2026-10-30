# 0010: Keycloak and Warpgate - authentication only, KeyClerk decides access

- Status: accepted (2026-10-23; derived from decisions 0004, 0005 and 0007 and proven in a lab; operator: "continue
  integrating with keycloak, we know we'll need that")
- Date: 2026-10-23
- Evidence: the lab harness (kept with the maintainer) - Keycloak 26.8.1 and a Warpgate release build on the lab box, driven through
  Warpgate's own e2e harness; results below.

## Context
Warpgate signs people in through an OIDC provider (`sso_providers`, type `custom`), matches the login to a Warpgate user
by SSO credential (e-mail plus provider), and can sync roles from a roles claim. ReliKey's rule is that KeyClerk,
through the edge agent, is the only writer of access (0004, 0007; KeyClerk 0013 D2), and that the core never connects
into the edge (0005).

## Decision
1. **One OIDC provider per edge: the core's Keycloak realm**, a confidential client per edge (`warpgate-<edge>`), PKCE
   (Warpgate uses it for custom providers), standard flow only, the redirect URI
   `https://<edge external host>/@warpgate/api/sso/return`. Passkey-only browser flow on that client (platform rule:
   passwordless).
2. **Authentication only.** The client carries no roles claim: no `warpgate_roles` or `warpgate_admin_roles` mapper,
   no `roles_claim` (and `role_mappings` holds only an unused key, below). Lab evidence: one hardcoded `warpgate_roles` mapper made Warpgate revoke a
   KeyClerk-granted, expiring role assignment on the next login (issue warp-tech/warpgate#2785). KeyClerk watches the
   client's protocol mappers as drift (pinned mapper hash, KeyClerk 0013 D4) and the agent refuses to run while one is
   present. Defence in depth: the provider sets `role_mappings` to a single key no IdP sends; Warpgate then manages only
   mapped roles, so even a roles claim added by mistake cannot revoke KeyClerk's assignments (verified live: with
   `role_mappings` set, the KeyClerk-granted role survived a login carrying `warpgate_roles`).
3. **No auto-creation.** `auto_create_users: false`. The agent provisions the Warpgate user and its SSO credential
   (provider name, e-mail) when a lease starts and removes them when it ends; a person without a lease is refused at
   login (lab: "No user matching ...").
4. **E-mail is the identity key, so only administrators change it.** The realm's user profile makes `email`
   admin-editable only; KeyClerk sets `emailVerified`. Warpgate refuses `email_verified: false` (lab) but trusts a
   missing claim, so the claim stays in the token. Binding to the subject instead is proposed upstream
   (warp-tech/warpgate#2787).
5. **No back-channel logout from Keycloak to the edge**: Warpgate 0.30.0 added OpenID Connect back-channel logout (the
   route `/@warpgate/api/sso/providers/<name>/backchannel-logout`), but using it would need Keycloak to connect into
   the edge (0005), so the route stays unused. Logout and revocation reach the edge as KeyClerk revocations in the
   bundle. Since 0.30.2 Warpgate itself ends a session when the role assignment that admitted it is revoked
   (warp-tech/warpgate#2789); the agent's close (0008) remains as the second line.
6. **Offline**, Warpgate's SSO is unavailable; sign-in follows decision 0006 (visit leases, phoned unlock, break-glass).

## Lab results (2026-10-23)
| Case | Result |
|---|---|
| Provisioned user, SSO credential, expiring role | signs in as that user; role intact |
| Keycloak user not provisioned in Warpgate | refused: "No user matching ..." |
| `emailVerified: false` in Keycloak | refused: "The SSO account's e-mail is not verified" |
| `warpgate_roles` hardcoded claim added on the client | the KeyClerk-granted role is revoked on the next login |
| the same claim, with `role_mappings` configured | the KeyClerk-granted role survives; SSO adds only its mapped role |
| role revoked, and role expired, during a live SSH session | the session keeps running (30 s and 40 s observed); a new session is refused |

Lab-only adjustments (not product configuration): Keycloak in `start-dev` on plain HTTP marks its login cookies
`Secure`, so the scripted client relaxes that flag; a real core serves Keycloak over HTTPS.

## Consequences
- Contract C-05 gains its Warpgate side: the per-edge client definition and the mapper drift check.
- The agent's lease application now includes Warpgate user and SSO-credential provisioning (C-01 widened).
- Upstream: #2785 (corrected publicly: a default-only footgun), #2786 (confirmed live), #2787 raised; #2788 closed as
  not reproduced. The PR plan is in `docs/upstream.md`.

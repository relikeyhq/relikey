# 0018: A vendor's people sign in through the vendor's own identity provider, pinned by subject

- Status: proposed (operator, 2026-10-24: "yes do all that", the SSO half of vendor access; a red team runs before
  acceptance)
- Date: 2026-10-24
- Builds on: 0010 (the broker authenticates, the agent provisions), C-05 (passkey-only sign-in), C-06 (visit leases),
  KeyClerk 0014 (edge visit leases for persons of kind external)

## Context
Remote maintenance by an equipment vendor is the access OT estates find hardest to control. KeyClerk already records it
(a person of kind external, their organisation among the connected organisations, an edge visit lease), and the agent
applies visit leases (C-06). What is missing is the sign-in: a vendor's engineer should not need a second password
managed by the plant, and the plant should not have to trust whatever the vendor's identity provider says.

Brokering an outside OpenID provider in Keycloak is standard. The usual setups hurt here: first-broker-login with
automatic linking finds the local account by e-mail, so a provider that asserts someone else's e-mail takes over that
account, and a broker that creates accounts on first sign-in lets the provider decide who exists.

## Decision (proposed)
1. **Per vendor, one OpenID provider** in the core broker (`realm.py vendor`): endpoints from its discovery document,
   issuer checked against it, tokens checked against its published keys, PKCE S256, nothing imported, no tokens stored,
   e-mail not trusted.
2. **Pinned by subject, never matched.** A brokered identity gets in only when it is already linked to a provisioned
   person by the provider's subject, its immutable id for them (`realm.py vendor-link`). The first-broker-login flow
   denies: an unlinked identity is never created, matched by e-mail or offered a link.
3. **The ReliKey passkey still applies.** After the vendor's sign-in the post-broker-login flow asks for the person's
   passkey; a person without one registers it as a required action before any session exists. So every edge keeps one
   sign-in level, passkey-only (KeyClerk session constraints S4). A person with neither a passkey nor that required
   action cannot be linked, and new persons get the registration as a default action.
4. **Access is still a lease.** Signing in decides nothing: what the person reaches is a visit lease or a lease from
   KeyClerk, enforced at the edge.
5. **Who links.** Until KeyClerk carries the binding (person, provider, subject) in its records and the reconciler
   applies it, `vendor-link` is an install-time action by the core's administrator, recorded in the broker's admin
   events. Linking is identity, not access: it adds no group, role or lease.

## Consequences
- A vendor's engineer uses their own company sign-in plus a passkey on the plant's side; the plant manages no vendor
  password.
- A compromised vendor provider can sign in only the persons linked to it, and only up to the passkey step.
- The vendor's provider learns which of its people sign in to the plant, and when.

## Residuals
- Changes to a linked person's required actions are broker admin actions, recorded in its admin events; a binding
  check belongs with the KeyClerk binding (point 5).
- Passkey freshness is checked per edge-wide sign-in, not per session (S4).

## Evidence
the lab harness (kept with the maintainer) against Keycloak 26.8.1 (the core's pin), one realm as the vendor's provider: an unlinked
identity is denied although a person with the asserted e-mail exists, and no account is created; a linked identity
reaches passkey registration and never a session without it; a passkey holder is asked for the passkey; relinking to
another subject and linking a person with no passkey path are refused.

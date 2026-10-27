# 0014: A sign-in gateway role in the one engine, for apps that only speak LDAP, local login or Kerberos

- Status: part A accepted (operator, 2026-10-25, with 0017); part B proposed, accepted after its prototype. Draft 3,
  the open questions decided in the operator's decide loop of 2026-10-25. Review:
  a review record kept with the maintainer (S-1..S-13).
- Date: 2026-10-24 (draft 1), 2026-10-25 (drafts 2 and 3)
- Amends: 0001 point 2 (a second exception beside the edge agent)
- Builds on: 0003 (LDAP lease credentials), 0010 (the broker), 0012 R-16 (one engine, attested profile), and the
  legacy sign-in proxy design of 2026-10-23 (header, Basic and form logins), summarised in the context below

## Context
Many production estates, Windows server farms among them, run applications whose only sign-in is integrated Windows
authentication (Kerberos), an LDAP bind, or the application's own local accounts. These cannot be given passkeys, an
approval, or a lease directly. The legacy sign-in proxy design (2026-10-23) covers header, Basic and form logins:
ReliKey in front as pattern P-C, a token per sign-in, Caddy forward_auth with a small token service, and a KeyClerk
LDAP reconciler. None of it covers Kerberos.

Presenting a modern sign-in to such an app as a Kerberos credential is done today mostly by commercial products, many
tied to a vendor cloud: Microsoft's Entra application proxy connector, F5 BIG-IP APM, Citrix NetScaler, Okta Access
Gateway, PingAccess (prior-art scan 2026-10-24). The open building blocks exist but are not packaged: MIT Kerberos
implements protocol transition (S4U, `gss_acquire_cred_impersonate_name`), gssproxy runs the S4U2Self step for
FreeIPA, and Apache mod_auth_gssapi can use S4U2Proxy (`GssapiUseS4U2Proxy`). What is missing in open source is the
proxy that turns an OIDC sign-in into a delegated ticket. The other route needs no delegation rights at all:
certificate logon (PKINIT), which Teleport uses for Windows desktops. Warpgate's vendored Kerberos library signs in to
RDP targets with stored credentials and offers no delegation.

0001 keeps protocol handling out of ReliKey, with the edge agent as the one exception, and the red teams of 0019,
0020 and 0021 each ended at "not in ReliKey". This decision proposes a second, narrow exception, and has to say why it
differs (the end of part A and of part B).

## Part A: the gateway role, LDAP and local login (accepted 2026-10-25)
1. **One engine, a second role.** The gateway is a role of the same `relikey` engine as the edge agent (0012 R-16),
   not a separate program and not a Warpgate fork. Both roles share the bundle verifier, the A/B state and floors, the
   pins, the attestation, and the status and metrics surfaces. The officer's ceiling and the attested profile decide
   which roles a box may run; local configuration may only switch a role off, never widen it.
2. **How a person reaches it.** Only as a bastion HTTPS target (pattern P-C, 0002): the person's session runs through
   Warpgate, so it is recorded and evidenced like any other; the application is reachable from the gateway alone, and
   the gateway strips any client-sent identity header before it adds its own (review S-4).
3. **How it signs a person in.** Through the broker only: one confidential OIDC client per gateway, as for each
   Warpgate (0010), the code flow with PKCE, a token whose audience is that client, checked, plus a current verified
   lease that admits this person to this application. The gateway never verifies a passkey itself; the broker does
   (0001 point 5) (review S-6).
4. **The lease decides every conversion.** A lease that has ended, or a desk unreachable beyond the class horizon,
   converts nothing. The gateway mints no access of its own authority; it presents a credential only on a verified
   lease, as the agent applies only a verified bundle.
5. **Two converters, off by default** (0001 point 6); turning one on records its purpose, the application it fronts
   and the accounts it excludes:
   - **LDAP bind** (0003): the application binds against ReliKey's LDAP facade, which answers from the directory the
     reconciler keeps in step. No new protocol work.
   - **Local login**: a per-application form or header adapter with a token per sign-in, as the 2026-10-23 design
     describes. Who holds a credential the application needs: point 7.
6. **External persons are excluded by default.** A vendor's identity (0018) and a visit lease are not converted
   unless the officer's ceiling names that application for them (review S-13).

7. **No stored person credential, with one named exception** (Q-1, decided 2026-10-25; review S-3). By default the
   local-login converter holds no credential for a person: a token per sign-in, or an application account the gateway
   holds as a workload credential, rotated on a schedule. Where an application's only sign-in is a local account per
   person, the officer's ceiling may name it, and the gateway then holds that person's credential for one lease's
   session only, never shown, rotated at session and lease end, never readable by the desk, and recorded as a
   residual for that application (0009 point 2, amended).

Why part A differs from 0019 to 0021: it adds no protocol into the legacy zone beyond what 0003's facade and pattern
P-C already carry; it is the existing facade and front, given an application as their client.

## Part B: the Kerberos converter (proposed; accepted after its prototype)
1. **What it carries:** HTTP Negotiate to the one application service it fronts. The ticket stays in the gateway,
   never handed to the client; RDP stays with Warpgate (review S-5).
2. **How: constrained delegation with protocol transition** (Q-2, decided 2026-10-25), by a dedicated account per
   fronted application, because services on one account can stand in for each other and the delegation scope is that
   account's (review S-8). Not certificate logon (PKINIT): a CA that AD trusts for logon can sign in as anyone in the
   domain, a broader power than delegation to one service. PKINIT stays with desktop logon, which is the bastion's
   (Teleport, the one bastion that does Kerberos, does it only by PKINIT, for RDP and SQL Server).
3. **Lifetime:** a ticket lives no longer than the lease's remainder, and the session ends when the lease ends; a
   revoke ends the gateway's session and discards its tickets (review S-7).
4. **Containment, refused at start without it:** privileged and administrative accounts are marked sensitive and not
   delegable in the directory, and refused by the ceiling; every conversion is a logged event in the evidence trail;
   the guards of the pre-build red team (G1 to G8) are build-time tests.
5. **The conduit, stated:** the gateway needs live reach to the domain controllers, a new conduit from the edge's zone
   into AD (IEC 62443-3-2). Offline, it converts nothing (review S-9).
6. **Where the delegating secret lives: one role, a secret-holder seam** (Q-3, decided 2026-10-25). The same gateway
   role runs on two hosts, and only the holder of the secret differs:
   - **default: a Windows member server inside the zone** with a group-managed service account; the operating system
     holds and rotates the secret, and the engine asks it for tickets without ever seeing a key;
   - **a Linux edge only when it attests the assured profile**, with the keytab sealed to its TPM and rotated by the
     engine; never a keytab in a plain file on a basic edge (pre-build red team G6).
   The converter never moves into the bastion: no other bastion does outbound delegation, so in the bastion it would
   be a one-product feature and a gap in every other's matrix (0016, 0023). Behind the bastion's HTTPS target it works
   behind any bastion.

**Residual, stated:** protocol transition lets the gateway obtain a ticket as any non-sensitive user to that one
service; only the lease check, in software, stands between the gateway's identity and that power. A compromised
gateway is therefore a compromise of that application for every non-sensitive user (review S-10).

Before acceptance, part B is prototyped on Linux in a throwaway lab (MIT Kerberos protocol transition against a Samba
AD domain), and the guards of the pre-build red team are run against the prototype.

Why part B differs from 0019 to 0021: the capability is not packaged in open source, no bastion offers it, and the
alternative is a commercial, often cloud-bound product in front of exactly the estates ReliKey serves.

## Consequences
- 0001 point 2 gains a second exception: the sign-in gateway, beside the edge agent. ReliKey
  still forks and patches no upstream component; any Warpgate change goes upstream (0012 R-01).
- NIST SP 800-207, stated: the gateway is an enforcement point that also presents credentials (part A: tokens and
  facade binds; part B: tickets). RFC 9700's code flow with PKCE and audience restriction applies (part A point 3).
- The edge's blast radius grows with part B to the applications it fronts; part A adds none beyond the facade.
- Not built: the gateway. This decision authorises design and review, not implementation.

## Prior art (scan 2026-10-24; corrected 2026-10-25)
| Product | Open? | Emits | Cloud-tied |
|---|---|---|---|
| Entra application proxy connector | no | Kerberos (KCD), header SSO | yes |
| F5 BIG-IP APM, Citrix NetScaler, Okta Access Gateway, PingAccess | no | Kerberos (KCD), Basic, header, forms | partly |
| MIT Kerberos S4U, gssproxy, mod_auth_gssapi (`GssapiUseS4U2Proxy`) | yes | the delegation steps, not an OIDC-fronted proxy | no |
| Teleport Windows desktop access | open core | short-lived certificates (PKINIT) for RDP | needs the cluster |

## Changelog
- 2026-10-25 Part A accepted (operator, with 0017); 0001 point 2 amended. Part B stays proposed until its prototype.
- 2026-10-25 Draft 3: Q-1 decided (no stored person credential; a per-session credential only for an application the
  ceiling names; 0009 point 2 amended), Q-2 decided (constrained delegation, not PKINIT), Q-3 decided (one role, a
  secret-holder seam: Windows gMSA by default, a TPM-sealed keytab only on an assured Linux edge; never in the
  bastion). Part A is accepted with 0017; part B after a prototype.
- 2026-10-25 Draft 2 after the review (S-1..S-13): split into part A (gateway role, LDAP, local login) and part B
  (Kerberos), accepted separately; behind the bastion; broker OIDC only; external persons excluded by default; Q-1
  (who holds a local-login credential, against 0009 M2), Q-2 (PKINIT instead of delegation), Q-3 (the host) open;
  ticket lifetime, per-application accounts, the AD conduit and the impersonation residual stated; prior art
  corrected; the private design notes summarised instead of cited.
- 2026-10-24 Proposed: the gateway as a second role of the one engine, amending 0001; LDAP and local login build on
  0003 and the 2026-10-23 design, Kerberos is new; review before build.

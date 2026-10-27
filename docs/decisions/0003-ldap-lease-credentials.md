# 0003: An LDAP-only system gets lease credentials, never a person's password

- Status: accepted (operator, 2026-10-23: as amended by 0007, 0008 and 0009 after red team 1)
- Date: 2026-10-23
- Amended by 0009: the credential is encrypted to the person's passkey-derived key, never a desk key; rotated after the
  first bind where the system binds once per login.
- Amended by 0008: point 5 withdrawn (Warpgate cannot inject per-user credentials yet, U-09); the person reaches the
  system through a Warpgate target and types the lease credential.
- Amended by 0005: the edge agent, not OpenBao, rotates facade passwords; the one-time hand-over goes through the
  KeyClerk desk, encrypted to the desk's key.

## Context
A system whose login can only perform an LDAP bind needs a password; the people using it sign in with passkeys and
have none (platform ADR-0056). Prior art (docs/prior-art.md): Strata Maverics mints a one-time credential after an IdP
sign-in (commercial); authentik lets a user create an expiring app password for LDAP binds after a web sign-in
(self-service, no approval, authentik is its own IdP); privacyidea-ldap-proxy checks OTPs at bind time. OpenBao's LDAP
secrets engine rotates static-role passwords and lends accounts out by check-out with a TTL.

## Decision
1. The legacy system binds against the appliance's LDAP facade (R-02) instead of its old directory. A person keeps the
   same account name, so the system's own mapping of users and roles is unchanged.
2. Outside a lease, no one knows any person's facade password: it is a random value nobody was shown.
3. A lease (granted by KeyClerk, with a second key where policy says so) rotates the person's facade password to a fresh
   random value and shows it once on the KeyClerk desk, after a fresh passkey sign-in. Lease end, early end or
   revocation rotates it again without showing it (contract C-03).
4. A lease credential is a machine-made secret bound to one lease; it is not a password in the sense of the
   passwordless rule (a person never chooses, reuses or recovers it). Its length and lifetime are configuration with
   secure defaults (short leases).
5. Where the system's UI is reachable through the bastion (P-A), the bastion injects the credential and the person
   never sees it.
6. Service accounts the legacy system itself uses to search the directory are workloads with an owner (KeyClerk 0011),
   rotated on a schedule; they never sign in a person.

## Consequences
- Between hand-over and lease end the credential can be copied: residual risk stated in `model/patterns.yaml` P-B.
- The facade must answer what legacy systems actually send (simple bind, search filters, memberOf, StartTLS): R-02
  needs a compatibility test set before a facade is chosen.

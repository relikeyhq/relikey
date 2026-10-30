# Security

ReliKey is security infrastructure: a weakness in it is a weakness in whatever it protects. Please treat findings
responsibly.

## Reporting a weakness

Report privately, never in a public issue or pull request, through a private security advisory on this repository:
https://github.com/relikeyhq/relikey/security/advisories/new

Include what you found, how to reproduce it, and the impact as you see it. We will agree a disclosure timeline with you
before anything is made public, and credit you if you want it.

### Response targets

- We acknowledge a report within 5 working days.
- For a confirmed issue we give you a fix or a plan with dates within 30 days.

These are targets for a small project, not guarantees; if we need longer we say so and why.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes, only the latest 0.1 patch release gets fixes |
| older | no |

## Scope

In scope: this repository's own code and model (the edge agent, `deploy/`, `tools/`, the contract checks) and the way
ReliKey composes its components. A finding in an upstream component itself (Keycloak, KeyClerk, Warpgate, OpenBao,
lldap) goes to that project; tell us too if the composition makes it worse. KeyClerk takes reports through GitHub's
private vulnerability reporting: https://github.com/keyclerk/keyclerk/security/advisories/new.

Out of scope here: the design's full threat model, residual-risk register and any live deployment. Those are kept with
the maintainer, not in this repository; ask privately if a report needs them.

## Status

ReliKey is early (see the README). It is meant to be stood up in a lab, not relied on in production yet; that does not
make a weakness less worth reporting.

## Cryptography and post-quantum status

ReliKey publishes an inventory of the cryptography on every link, signed format and long-lived key, with its quantum
status ([docs/reference/crypto.md](docs/reference/crypto.md), also as a CycloneDX CBOM). The edge agent's links to the
core and to the bastion require hybrid post-quantum key exchange (X25519MLKEM768) and refuse a peer without it; other
links prefer it where both ends support it. Signatures, officer keys and passkeys are still classical, with a documented
migration plan (decision 0022). Nothing else in ReliKey is post-quantum, and this page will say so when that changes.

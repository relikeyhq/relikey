# Roadmap

Where ReliKey stands and where it goes next. Each line points at its issue; the milestones hold the detail and the
order of work. Decisions behind the larger items are in [docs/decisions](docs/decisions/README.md).

## Done in 0.1.x
- The edge agent: one static Go binary for amd64, arm64 and armv7 that applies signed decisions, works offline,
  and is tested with conformance vectors, mutation testing and fuzzing.
- The core composition on rootless podman and rootful docker; passkey sign-in, leases applied on the bastion,
  recorded sessions and revocation, proven in lab runs on one host.
- The fleet service with signed reports, the officer registry and enrolment by code (built and tested).
- Releases: signed tags, binaries built reproducibly twice and compared, SHA256SUMS and build provenance
  (0.1.2 is the first published release).

## Done in [0.2.0](https://github.com/relikeyhq/relikey/milestone/1)
Released as 0.2.1 (the v0.2.0 tag was never released: its release build stopped at the SBOM attestation).
- A demo that runs ReliKey against fakes in one command, and a docs site built from `docs/` with it as the first
  tutorial ([#40](https://github.com/relikeyhq/relikey/issues/40),
  [#42](https://github.com/relikeyhq/relikey/issues/42)).
- The agent: state written only when it changes, sequence numbers and a hash chain for its events, the credential
  policy for existing credentials, a retried bastion read, and metric names that are a stable interface, readable
  without a listener ([#10](https://github.com/relikeyhq/relikey/issues/10),
  [#11](https://github.com/relikeyhq/relikey/issues/11), [#18](https://github.com/relikeyhq/relikey/issues/18),
  [#19](https://github.com/relikeyhq/relikey/issues/19), [#53](https://github.com/relikeyhq/relikey/issues/53),
  [#54](https://github.com/relikeyhq/relikey/issues/54), [#60](https://github.com/relikeyhq/relikey/issues/60)).
- The fleet: activation and the installer's side of enrolment by code wired, and the core installer writes its
  settings ([#9](https://github.com/relikeyhq/relikey/issues/9), [#74](https://github.com/relikeyhq/relikey/issues/74)).
- The edge on Warpgate 0.30.2 ([#78](https://github.com/relikeyhq/relikey/issues/78)).
- Releases: only a commit that passed CI is released, binaries smoke-tested, an SBOM for each binary, base images
  pinned by digest, Scorecard's Go advisories cleared ([#13](https://github.com/relikeyhq/relikey/issues/13),
  [#14](https://github.com/relikeyhq/relikey/issues/14), [#17](https://github.com/relikeyhq/relikey/issues/17),
  [#55](https://github.com/relikeyhq/relikey/issues/55), [#92](https://github.com/relikeyhq/relikey/issues/92)).
- The model re-statused against evidence and audited against the code, conformance vectors at KeyClerk 0.26.3
  ([#12](https://github.com/relikeyhq/relikey/issues/12), [#15](https://github.com/relikeyhq/relikey/issues/15),
  [#61](https://github.com/relikeyhq/relikey/issues/61)).
- Project hygiene: mutants per pull request, job timeouts and CODEOWNERS, changelog fragments, SECURITY.md, errors
  that say why and what to do next, this file ([#7](https://github.com/relikeyhq/relikey/issues/7),
  [#8](https://github.com/relikeyhq/relikey/issues/8), [#16](https://github.com/relikeyhq/relikey/issues/16),
  [#20](https://github.com/relikeyhq/relikey/issues/20), [#21](https://github.com/relikeyhq/relikey/issues/21),
  [#22](https://github.com/relikeyhq/relikey/issues/22), [#52](https://github.com/relikeyhq/relikey/issues/52),
  [#58](https://github.com/relikeyhq/relikey/issues/58)).

## Next: [0.3.0](https://github.com/relikeyhq/relikey/milestone/2)
Work that needs a lab installation, hardware or a second component. Done so far:
- Keyless signatures and SLSA Build L3 ([#28](https://github.com/relikeyhq/relikey/issues/28), released in 0.2.1)
- Signed container images on ghcr.io ([#29](https://github.com/relikeyhq/relikey/issues/29), released in 0.2.1)
- Enrolment-key rotation ([#26](https://github.com/relikeyhq/relikey/issues/26), released in 0.2.1)

Open, suggested order:
1. End-to-end test of enrolment and the officer anchor on a fresh installation ([#23](https://github.com/relikeyhq/relikey/issues/23))
2. Model: the edge proxy's footprint, measured against the switch profile ([#62](https://github.com/relikeyhq/relikey/issues/62))
3. Evidence log: core witness, anchoring, contracts C-12 and C-13 ([#25](https://github.com/relikeyhq/relikey/issues/25))
4. Open contracts C-02, C-03, C-07, C-08, C-09, C-11 ([#27](https://github.com/relikeyhq/relikey/issues/27))
5. VEX statements with each release ([#30](https://github.com/relikeyhq/relikey/issues/30))
6. Operator guides: install, run, troubleshoot ([#43](https://github.com/relikeyhq/relikey/issues/43))
7. Demo: a single click from the README ([#41](https://github.com/relikeyhq/relikey/issues/41))
8. The armv7 agent on real hardware ([#24](https://github.com/relikeyhq/relikey/issues/24))
9. IEC 62443-4-1 self-assessment ([#31](https://github.com/relikeyhq/relikey/issues/31))

## Later: [deferred](https://github.com/relikeyhq/relikey/milestone/3)
Accepted or proposed direction that waits on a partner release, a prototype or a decision:
- OCSF log events from the agent ([#32](https://github.com/relikeyhq/relikey/issues/32))
- Fleet: signed release manifest, relay and staged rollout ([#33](https://github.com/relikeyhq/relikey/issues/33))
- Sign-in gateway part A: LDAP facade and local login ([#34](https://github.com/relikeyhq/relikey/issues/34))
- Sign-in gateway part B: a Kerberos prototype ([#35](https://github.com/relikeyhq/relikey/issues/35))
- Vendor sign-in through the vendor's own identity provider ([#36](https://github.com/relikeyhq/relikey/issues/36))
- Production networking and high availability for the core ([#37](https://github.com/relikeyhq/relikey/issues/37))
- Edge on Windows: what it takes, behind Warpgate's Windows port ([#81](https://github.com/relikeyhq/relikey/issues/81))

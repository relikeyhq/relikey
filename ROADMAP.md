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

## Next: [0.2.0](https://github.com/relikeyhq/relikey/milestone/1)
Finish what 0.1.x started. Suggested order:
1. Agent: write state only when it changes ([#11](https://github.com/relikeyhq/relikey/issues/11))
2. CI: run the mutants a pull request can affect ([#7](https://github.com/relikeyhq/relikey/issues/7))
3. CI hygiene: job timeouts, CODEOWNERS, a docs check ([#20](https://github.com/relikeyhq/relikey/issues/20))
4. Release gate and smoke test ([#13](https://github.com/relikeyhq/relikey/issues/13))
5. README: verifying a release, accurate status ([#8](https://github.com/relikeyhq/relikey/issues/8))
6. Model: re-status C-01, C-04, C-10 ([#12](https://github.com/relikeyhq/relikey/issues/12))
7. Conformance vectors at KeyClerk 0.26.3 ([#15](https://github.com/relikeyhq/relikey/issues/15))
8. SECURITY.md: supported versions and response targets ([#16](https://github.com/relikeyhq/relikey/issues/16))
9. Containerfiles pinned by digest ([#17](https://github.com/relikeyhq/relikey/issues/17))
10. An SBOM for each binary ([#14](https://github.com/relikeyhq/relikey/issues/14))
11. Fleet: wire activation and the installer's side of enrolment ([#9](https://github.com/relikeyhq/relikey/issues/9))
12. Agent: credential policy for existing credentials ([#18](https://github.com/relikeyhq/relikey/issues/18))
13. Agent: retry a transient bastion read ([#19](https://github.com/relikeyhq/relikey/issues/19))
14. Agent: sequence numbers and a hash chain for events ([#10](https://github.com/relikeyhq/relikey/issues/10))
15. Errors say why and what to do next ([#22](https://github.com/relikeyhq/relikey/issues/22))
16. This file ([#21](https://github.com/relikeyhq/relikey/issues/21))

## Then: [0.3.0](https://github.com/relikeyhq/relikey/milestone/2)
Work that needs 0.2.0 first, a lab installation, hardware or a second component:
- End-to-end test of enrolment and the officer anchor on a fresh installation ([#23](https://github.com/relikeyhq/relikey/issues/23))
- The armv7 agent on real hardware ([#24](https://github.com/relikeyhq/relikey/issues/24))
- Evidence log: core witness, anchoring, contracts C-12 and C-13 ([#25](https://github.com/relikeyhq/relikey/issues/25))
- Enrolment-key rotation ([#26](https://github.com/relikeyhq/relikey/issues/26))
- Open contracts C-02, C-03, C-07, C-08, C-09, C-11 ([#27](https://github.com/relikeyhq/relikey/issues/27))
- Keyless signatures and SLSA Build L3 ([#28](https://github.com/relikeyhq/relikey/issues/28))
- Signed container images on ghcr.io ([#29](https://github.com/relikeyhq/relikey/issues/29))
- VEX statements with each release ([#30](https://github.com/relikeyhq/relikey/issues/30))
- IEC 62443-4-1 self-assessment ([#31](https://github.com/relikeyhq/relikey/issues/31))

## Later: [deferred](https://github.com/relikeyhq/relikey/milestone/3)
Accepted or proposed direction that waits on a partner release, a prototype or a decision:
- OCSF log events from the agent ([#32](https://github.com/relikeyhq/relikey/issues/32))
- Fleet: signed release manifest, relay and staged rollout ([#33](https://github.com/relikeyhq/relikey/issues/33))
- Sign-in gateway part A: LDAP facade and local login ([#34](https://github.com/relikeyhq/relikey/issues/34))
- Sign-in gateway part B: a Kerberos prototype ([#35](https://github.com/relikeyhq/relikey/issues/35))
- Vendor sign-in through the vendor's own identity provider ([#36](https://github.com/relikeyhq/relikey/issues/36))
- Production networking and high availability for the core ([#37](https://github.com/relikeyhq/relikey/issues/37))

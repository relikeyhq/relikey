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
1. Demo: one command that runs ReliKey against fakes ([#40](https://github.com/relikeyhq/relikey/issues/40))
2. Agent: write state only when it changes ([#11](https://github.com/relikeyhq/relikey/issues/11))
3. CI: run the mutants a pull request can affect ([#7](https://github.com/relikeyhq/relikey/issues/7))
4. CI hygiene: job timeouts, CODEOWNERS, a docs check ([#20](https://github.com/relikeyhq/relikey/issues/20))
5. Release gate and smoke test ([#13](https://github.com/relikeyhq/relikey/issues/13))
6. README: verifying a release, accurate status ([#8](https://github.com/relikeyhq/relikey/issues/8))
7. Docs site built from `docs/`, the demo as its first tutorial ([#42](https://github.com/relikeyhq/relikey/issues/42))
8. Model: re-status C-01, C-04, C-10 ([#12](https://github.com/relikeyhq/relikey/issues/12))
9. Conformance vectors at KeyClerk 0.26.3 ([#15](https://github.com/relikeyhq/relikey/issues/15))
10. SECURITY.md: supported versions and response targets ([#16](https://github.com/relikeyhq/relikey/issues/16))
11. Containerfiles pinned by digest ([#17](https://github.com/relikeyhq/relikey/issues/17))
12. An SBOM for each binary ([#14](https://github.com/relikeyhq/relikey/issues/14))
13. Fleet: wire activation and the installer's side of enrolment ([#9](https://github.com/relikeyhq/relikey/issues/9))
14. Agent: credential policy for existing credentials ([#18](https://github.com/relikeyhq/relikey/issues/18))
15. Agent: retry a transient bastion read ([#19](https://github.com/relikeyhq/relikey/issues/19))
16. Agent: sequence numbers and a hash chain for events ([#10](https://github.com/relikeyhq/relikey/issues/10))
17. Errors say why and what to do next ([#22](https://github.com/relikeyhq/relikey/issues/22))
18. This file ([#21](https://github.com/relikeyhq/relikey/issues/21))
19. Changelog entries as fragments, so pull requests stop conflicting ([#52](https://github.com/relikeyhq/relikey/issues/52), done)
20. Issue chooser: the private-report link names the wrong owner ([#58](https://github.com/relikeyhq/relikey/issues/58))
21. Installers: run the helper image by digest, as the images are ([#55](https://github.com/relikeyhq/relikey/issues/55))
22. Model: an audit against the code, and a gate rule for the drift it finds ([#61](https://github.com/relikeyhq/relikey/issues/61))
23. Model: the edge proxy's footprint, measured against the switch profile ([#62](https://github.com/relikeyhq/relikey/issues/62))
24. Agent: its metric names are a stable interface ([#53](https://github.com/relikeyhq/relikey/issues/53))
25. Agent: metrics a site's monitoring can read, without a listener ([#60](https://github.com/relikeyhq/relikey/issues/60))
26. Agent: the writes left on idle ticks and unchanged pulls ([#54](https://github.com/relikeyhq/relikey/issues/54))
27. Core installer: write the fleet's enrolment-by-code settings ([#74](https://github.com/relikeyhq/relikey/issues/74))
28. Edge: Warpgate 0.30.2, and decision 0010 brought up to date ([#78](https://github.com/relikeyhq/relikey/issues/78))

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
- Demo: a single click from the README ([#41](https://github.com/relikeyhq/relikey/issues/41))
- Operator guides: install, run, troubleshoot ([#43](https://github.com/relikeyhq/relikey/issues/43))

## Later: [deferred](https://github.com/relikeyhq/relikey/milestone/3)
Accepted or proposed direction that waits on a partner release, a prototype or a decision:
- OCSF log events from the agent ([#32](https://github.com/relikeyhq/relikey/issues/32))
- Fleet: signed release manifest, relay and staged rollout ([#33](https://github.com/relikeyhq/relikey/issues/33))
- Sign-in gateway part A: LDAP facade and local login ([#34](https://github.com/relikeyhq/relikey/issues/34))
- Sign-in gateway part B: a Kerberos prototype ([#35](https://github.com/relikeyhq/relikey/issues/35))
- Vendor sign-in through the vendor's own identity provider ([#36](https://github.com/relikeyhq/relikey/issues/36))
- Production networking and high availability for the core ([#37](https://github.com/relikeyhq/relikey/issues/37))

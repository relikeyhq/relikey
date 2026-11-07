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

## Next: [0.3.0](https://github.com/relikeyhq/relikey/milestone/2), due 2026-11-19
Edge protocol 1.4 end to end, the core on KeyClerk 0.28.0, and the lab and desk work that needs no new hardware.
Done:
- Keyless signatures and SLSA Build L3 ([#28](https://github.com/relikeyhq/relikey/issues/28), released in 0.2.1)
- Signed container images on ghcr.io ([#29](https://github.com/relikeyhq/relikey/issues/29), released in 0.2.1)
- Enrolment-key rotation ([#26](https://github.com/relikeyhq/relikey/issues/26), released in 0.2.1); it finishes in the edge pod: the key in a writable directory,
  `install.py move-keys` for older installs ([#134](https://github.com/relikeyhq/relikey/issues/134))
- VEX statements with each release ([#30](https://github.com/relikeyhq/relikey/issues/30))
- Edge protocol 1.4 in the agent: conformance vectors at KeyClerk 0.27.0, the records head echoed, removals confirmed,
  `lease_ended_early` incidents and the bastion's declaration in the report ([#116](https://github.com/relikeyhq/relikey/issues/116))
- The edge on Warpgate 0.30.4, with a live test of the agent's adapter against the real API ([#117](https://github.com/relikeyhq/relikey/issues/117))
- The core on KeyClerk 0.28.0 (by way of 0.27.0: approvals on a passkey sign-in) ([#118](https://github.com/relikeyhq/relikey/issues/118), [#141](https://github.com/relikeyhq/relikey/pull/141))
- Enforce mode refuses a time namespace that offsets its clocks ([#123](https://github.com/relikeyhq/relikey/issues/123))
- Each start of the agent is an event, so an idle edge's chain can be checked across a restart ([#129](https://github.com/relikeyhq/relikey/pull/129))
- The demo as a signed image that runs offline, beside the Codespaces route ([#41](https://github.com/relikeyhq/relikey/issues/41))
- Operator guides: install, run, troubleshoot, overview ([#43](https://github.com/relikeyhq/relikey/issues/43): written; done once walked on a fresh install)

Open: the release candidate `v0.3.0-rc.1`, then one walk of a fresh installation on it, following the operator guides:
enrolment by code and the officer anchor with real passkeys ([#23](https://github.com/relikeyhq/relikey/issues/23), [#43](https://github.com/relikeyhq/relikey/issues/43)); fixes from the walk, then `v0.3.0`.

## Then: [0.4.0](https://github.com/relikeyhq/relikey/milestone/4), due 2026-12-17
Edge protocol 1.5, a second edge node, and what a first pilot asks for first: how updates reach an edge safely, and
a named person behind a legacy system's shared account. In review:
- Edge protocol 1.5 in the agent: the trusted time ratchets, so a frozen boot clock and a wall clock set back cannot
  stretch a lease ([#125](https://github.com/relikeyhq/relikey/issues/125), [#142](https://github.com/relikeyhq/relikey/pull/142))
- A second edge node (decision 0028): a warm spare that shows people the same host key and certificate, taken over by
  hand with the site key's promotion statement ([#127](https://github.com/relikeyhq/relikey/issues/127); site keys merged, `promote` in [#143](https://github.com/relikeyhq/relikey/pull/143)). Automatic failover
  with two whole edges is designed and kept ready behind a trigger.

Open:
1. The spare's takeover walked in the lab, with the fleet admitting the spare ([#127](https://github.com/relikeyhq/relikey/issues/127))
2. Signed agent updates, verified on the edge (contract C-11, [#27](https://github.com/relikeyhq/relikey/issues/27))
3. A fresh LDAP credential per lease for a legacy system's shared account (contract C-03, [#27](https://github.com/relikeyhq/relikey/issues/27))

An item that is not done by about 2026-12-10 moves to 0.5.0; the date does not move.

## Then: [0.5.0](https://github.com/relikeyhq/relikey/milestone/5)
Edge protocol 1.6 with KeyClerk 0.29.0, the evidence log, and working offline and on small hardware:
1. The core on KeyClerk 0.29.0: the identity-map pin, the bundle and unlock keys in the signer ([#140](https://github.com/relikeyhq/relikey/pull/140)); a promotion
   statement that expires (edge protocol 1.6, [#148](https://github.com/relikeyhq/relikey/pull/148))
2. Staged update rollout across a fleet ([#33](https://github.com/relikeyhq/relikey/issues/33))
3. Evidence log: core witness, anchoring, contracts C-12 and C-13 ([#25](https://github.com/relikeyhq/relikey/issues/25))
4. Phoned unlock end to end and the break-glass credential (contracts C-08, C-09, [#27](https://github.com/relikeyhq/relikey/issues/27))
5. Carried visit leases ([#128](https://github.com/relikeyhq/relikey/issues/128))
6. IPv6: state the support and walk it, dual-stack and IPv6-only ([#139](https://github.com/relikeyhq/relikey/issues/139))
7. The agent on real armv7 and arm64 hardware ([#24](https://github.com/relikeyhq/relikey/issues/24)), the edge proxy's footprint measured on it ([#62](https://github.com/relikeyhq/relikey/issues/62)), and the
   reference hardware for an assured edge chosen
8. IEC 62443-4-1 self-assessment ([#31](https://github.com/relikeyhq/relikey/issues/31))

## Then: [0.6.0](https://github.com/relikeyhq/relikey/milestone/6)
What opens the remaining scenarios: offline visits on an attested edge, a second person at the start of a session, and
an edge that runs natively on a site's own Windows Server.
1. An assured edge: TPM attestation, which visit leases need ([#146](https://github.com/relikeyhq/relikey/issues/146))
2. Session-start approval by a second person, from KeyClerk 0.30.0 (edge protocol 1.7, contract C-02, [#147](https://github.com/relikeyhq/relikey/issues/147))
3. The edge on Windows: Warpgate and the agent as Windows services from a native installer, no containers, on an
   up-to-date Windows Server in the same enclave as the legacy systems; a decision record sets its trust ceiling first
   ([#81](https://github.com/relikeyhq/relikey/issues/81), behind Warpgate's Windows port)

The order from 0.4.0 to 0.6.0 follows four reference deployments: OT on Windows, OT on Linux, legacy Windows IT, and a
critical service with a twin site. Each item traces to what one of them needs.

## Later: [deferred](https://github.com/relikeyhq/relikey/milestone/3)
Accepted or proposed direction that waits on a partner release, a prototype or a decision; each gets a date when
its dependency lands:
- OCSF log events from the agent ([#32](https://github.com/relikeyhq/relikey/issues/32))
- Sign-in gateway part A: LDAP facade and local login ([#34](https://github.com/relikeyhq/relikey/issues/34))
- Sign-in gateway part B: a Kerberos prototype ([#35](https://github.com/relikeyhq/relikey/issues/35))
- Vendor sign-in through the vendor's own identity provider ([#36](https://github.com/relikeyhq/relikey/issues/36))
- Production networking and high availability for the core ([#37](https://github.com/relikeyhq/relikey/issues/37))

# Changelog

All notable changes to ReliKey are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The public history starts at 0.1.0, the first public
release; its entry sums up the work before it (decision 0027).

## Versioning

Releases are semver tags, `v0.1.0` first. A ReliKey release is its pins and its configuration (decision
0001): each release lists the component versions it composes, as below, and its images by digest in
`model/components.yaml`.

### Pins in 0.2.0

| Component | Version | Image |
|---|---|---|
| Keycloak | 26.8.1 | `quay.io/keycloak/keycloak` |
| Broker database | 16.8-alpine | `docker.io/library/postgres` |
| Front proxy | 2.11.7-alpine | `docker.io/library/caddy` |
| KeyClerk | 0.26.3 | `localhost/keyclerk`, built from the signed source tag on github.com/keyclerk/keyclerk |
| Warpgate | 0.30.2 | `ghcr.io/warp-tech/warpgate` |
| Edge filtering proxy | 2.11.7-alpine | `docker.io/library/caddy` |
| LDAP facade | 0.6.3 | `docker.io/lldap/lldap` |
| Update mirror | v2.1.22 | `ghcr.io/project-zot/zot` |

### Pins in 0.1.0

| Component | Version | Image |
|---|---|---|
| Keycloak | 26.8.1 | `quay.io/keycloak/keycloak` |
| Broker database | 16.8-alpine | `docker.io/library/postgres` |
| Front proxy | 2.11.7-alpine | `docker.io/library/caddy` |
| KeyClerk | 0.26.3 | `localhost/keyclerk`, built from the signed source tag on github.com/keyclerk/keyclerk |
| Warpgate | 0.30.1 | `ghcr.io/warp-tech/warpgate` |
| LDAP facade | 0.6.3 | `docker.io/lldap/lldap` |
| Update mirror | v2.1.22 | `ghcr.io/project-zot/zot` |

## [Unreleased]

## [0.2.1] - 2026-11-04

### Added
- Enrolment-key rotation (decision 0026 slice 5): with a next key staged in `agent.json`
  (`next_enrolment_key_file`, `rotation_statement_file`), the agent answers the desk's 401 after KeyClerk's
  `rotate_edge` by signing the same request with the staged key, and only when the desk takes it swaps the key files
  (one rename, crash-safe) and signs with the new key from then on; a 401 the staged key does not cure changes nothing.
  The agent hands the new key to the fleet (`POST /fleet/v1/rotation`, signed by both keys, carrying the desk's
  statement); the fleet page lists it as pending, and an officer approves it with their passkey after typing 20
  characters of the new key from the desk's record. Until then reports go on with the old key; after it the fleet
  refuses the old key and the agent deletes it. A rotation that also changes the edge's officer is refused at start
  (`docs/agent.md`, "Rotating the enrolment key"; `docs/fleet.md`).
- The release build runs in a reusable workflow, `release-build.yml`, which the release workflow calls once CI passed
  on the tagged commit: every attestation and signature names it as the builder, and the calling workflow cannot
  change the build steps (SLSA Build L3). `SHA256SUMS` and each binary also get a keyless cosign signature, a Sigstore
  bundle `FILE.sigstore.json` among the release files, checked with `cosign verify-blob` (README.md, "Verifying a
  release", step 5).
- Each release publishes the agent and fleet images on ghcr.io (`relikey-agent` for amd64, arm64 and armv7,
  `relikey-fleet` for amd64 and arm64), built from the release's own binaries by `tools/release_images.py`, with a
  provenance attestation in the registry and a keyless cosign signature, and lists their digests in the release
  notes (README.md, "Verifying a release"). Pull requests build both images for every platform without pushing. The
  images' preparation stage runs on the build platform, so no emulation is needed.
- A release candidate tag `vX.Y.Z-rc.N` runs the whole release build and publishes a GitHub pre-release,
  never the latest release, with the changes in `changelog.d/` as its notes (docs/publishing.md).

### Fixed
- Each binary's SBOM carries a serial number again, a UUIDv5 of its content, so the SBOM attestation step
  accepts it; the 0.2.0 release build stopped there.

## [0.2.0] - 2026-11-03

Tagged, never released: the release build stopped at the SBOM attestation (fixed in 0.2.1, which is the first
release with these changes).

### Added
- Fleet enrolment by code, wired end to end (decision 0026 points 15, 24, 32, 33): the edge installer takes the
  slot code from a file (`--enrol-code-file`, or `install.py enrol --code-file` for an installed edge), presents the
  edge's key over TLS that trusts only the fleet's CA the code pins (never a leaf; Python 3.13 or later) and prints
  its fingerprint; an officer activates the slot on the fleet page with their passkey, typing 80 bits of the
  fingerprint (16 characters, not the last 16, or all of it) as read from the edge's screen; the edge's reports are
  then taken in. The enrolment route takes at most 20 presentations a minute, three refusals close a slot, and an
  enrolled name is never opened or activated again under another key.
- The agent's events form a hash chain (decision 0025 point 2, first part): every record carries its sequence
  number (OCSF `metadata.sequence`) and the sha256 of the line before it, the sequence survives a restart (each run
  opens a new epoch), the chain head is kept crash-safe in the state directory and reported in `status.json` as
  `event_chain`, and `events.Verify` shows a record removed, reordered or altered.
- A release is built only from a commit whose CI run passed on `main`: `release.yml` checks it first
  (`tools/release_gate.py`, waiting for a run still in progress), so a tag on a broken commit fails before anything is
  built. The built binaries are then smoke-tested (`build.py smoke`): those for the runner's architecture must run and
  report the tag's version and commit, the others must be ELF files for their target. `relikey-fleet -version` prints
  its version, commit and Go release, like the agent's `version`.
- Each released binary has a CycloneDX SBOM (`NAME.cdx.json`, made by `cyclonedx-gomod` from the binary's module data,
  reproducible like the binary), listed in `SHA256SUMS`, covered by the build provenance attestation and attested as
  the binary's SBOM. README.md, "Verifying a release", shows how to check one.
- CI hygiene: every workflow job has a `timeout-minutes`, `.github/CODEOWNERS` names the maintainer, and
  `tests/test_doc_links.py` fails a pull request when a relative Markdown link or #anchor in the docs does not resolve.
- `relikey-demo`: one command (`go run ./cmd/relikey-demo` in `agent/`) runs the real edge agent loop against
  stand-ins for KeyClerk, Warpgate and the identity broker, and shows a sign-in, a lease applied, a session, a revoke
  that removes the access and a lease that ends while the edge is offline, on a local page. Keys are generated per
  run, everything listens on loopback and nothing is left behind; CI plays the story headless (`docs/demo.md`).
- The demo opens from the README in a GitHub Codespace (`.devcontainer/`), and `-wait` starts its story when the
  page is first opened.
- Documentation site: `docs/` and the README built with MkDocs Material (`mkdocs.yml`, hash-locked
  `requirements-docs.txt`) and published to GitHub Pages from `main` by `.github/workflows/docs.yml`; every pull
  request builds it in strict mode, so a broken link fails CI.
- Changelog fragments: a pull request adds `changelog.d/<issue>.<section>.md` instead of editing `CHANGELOG.md`, so
  open pull requests no longer conflict with each other; `tools/changelog.py` checks them and folds them into the
  release section when a release is prepared.
- The agent's ten metric names in `metrics.prom` are a stable interface: a test pins each name and its type, and
  `docs/agent.md` lists them with their meaning. A rename or removal lands only in a tagged release, under Changed
  or Removed.
- Agent: `metrics_dir` (optional) writes a copy of `metrics.prom` as `relikey-agent.prom` to a directory of its own,
  replaced atomically and readable by other users, for node_exporter's textfile collector or a similar reader; the
  state directory stays private and the agent still serves nothing. A missing or unwritable directory is reported in
  the log and `status.json` (`metrics_dir_error`) and never stops the agent. The image carries
  `/var/lib/relikey-metrics` for it.
- The core installer writes enrolment by code: with `--fleet-host`, fleet.json gets its `admin` section once (kept
  on later runs, so the fleet never changes its id in passing) and the page its `enrol_url` on the edge-facing name
  and its `pin_ca_file`, the CA that issued the front's certificate (decision 0026 point 27). The local CA's
  `front.crt` now holds the leaf followed by the CA; without an issuing CA in `front.crt` enrolment stays off and the
  installer says why and what to do.
- docs/maintaining.md: how issues, milestones, pull requests, the required checks, merging and releases work.

### Changed
- The base image of the fleet and agent images (busybox 1.37.0) is pinned by its multi-arch index digest, and the two
  image files are renamed `Dockerfile.fleet` and `Dockerfile.agent` so Dependabot's docker ecosystem proposes updates
  to the pin weekly.
- CI: a pull request runs only the mutants it can affect (`agent/mutants.py --changed BASE`: those in a changed file
  or in a package whose tests changed, all of them when a shared test helper or the harness changed); main, a nightly
  schedule and a manual run take the full set in four parallel shards (`--shard i/n`).
- The agent's state store skips a write when the record is unchanged, so idle ticks and pulls that bring nothing new
  never rewrite the state slots, sparing the flash that edge hardware often boots from (AG-14). A test counts the
  slot writes over idle ticks; a mutant that always writes is killed.
- The model marks contracts C-01 (lease as role assignment), C-04 (signed lease bundles) and C-10 (per-edge ceiling)
  as built, each naming the agent tests that show it; C-10 also names what is not yet applied (hardware attestation,
  remote-reach mode and ports).
- The agent's KeyClerk conformance vectors are regenerated from the signed 0.26.3 tag (cfc5793), the version the
  release pins; `edge.json` is byte-identical to the 0.26.1 vectors and the agent passes all of it.
- SECURITY.md: a supported-versions table (0.1.x, latest patch only), response-time targets and a direct link to
  private vulnerability reporting.
- README: a "Verifying a release" section (tag signature, checksums, build provenance) and a Status paragraph that
  separates what releases carry since 0.1.2 from fleet-enforced signed releases, which are not done.
- Errors say why and what to do next: the installers' refusals, the agent's configuration, key and usage errors,
  its health report, the fleet service's configuration errors and the fleet page's role refusal now name the value
  at fault and the step, command or person that completes the task. A missing role on the fleet page points to
  `fleet_page.py --grant`. The edge installer checks the bundle and officer keys before it writes anything, instead
  of the agent refusing them at its first start. CONTRIBUTING.md holds the guideline for new messages.
- The core and edge installers and the fleet page run their helper busybox (owners of the secrets, reading a secret
  into a pipe, Warpgate's first setup) by the digest their image file pins, read from that file, instead of the
  1.37.0 tag; a test refuses a busybox reference by tag anywhere in `deploy/`.
- The model matches what ships: the edge's filtering proxy is recorded as the pinned Caddy front it was built as, and
  the LDAP facade carries the tag and digest the edge runs. C-05 names the configuration that builds it, and C-08 and
  C-09 say which part exists (the phoned-unlock code and its vectors; leaving the break-glass account alone).
- `tools/check_model.py` refuses a shipped compose file whose upstream image is not pinned by tag and digest, is named
  by no component of that tier, or differs from the component's version or digest.
- The model carries the measured footprint of the edge's pinned Caddy proxy (about 50 MB resident at idle, a 67 MB
  image, a first amd64 measurement) instead of the 15 MB estimated for a minimal proxy. The edge then needs about
  282 MB against the switch app-hosting profile's 256 MB: the profile records this as a known gap (issue, settling
  release, the open decision it waits on, the accepted memory need), and the model check warns on it instead of
  failing, but fails on a gap that is incomplete, waits on a settled decision, is outgrown, or is no longer needed.
  The remedy is chosen in 0.3.0 after measuring on the reference hardware.
- Edge: Warpgate 0.30.2, pinned by its multi-arch index digest (it ends a session itself when the role assignment
  that admitted it is revoked, so the agent's close is now the second line). Decision 0010 now records that Warpgate
  accepts OIDC back-channel logout and why the edge does not use it.
- Docs: the KeyClerk edge interface page maps edge protocol 1.1 to 1.3 to the agent and names the vendored vectors
  (KeyClerk v0.26.1); decision 0026 records what of the fleet is built and what is still open (#33, #26).
- CodeQL runs as a workflow (advanced setup) on pull requests, the merge queue, main and weekly, with the same
  languages and check names as the default setup it replaces, which did not run on the merge queue.
- CI runs on the merge queue (`merge_group`): the checks a pull request needs, with the mutants it can affect;
  every mutant still runs on main, nightly and on demand.
- ROADMAP lists the issues raised during the 0.2.0 work (#52 to #62, #74, #78) and #81 under Later; the agent
  guide no longer names a stale mutant count.

### Fixed
- The agent applies the account credential policy to credentials that were there before it: a password,
  one-time-password seed or client certificate on a managed account is removed on the next tick in enforce mode
  (reported in shadow mode), however it got there, and also while a failed session close holds the account; a
  credential list that cannot be read makes the account unreadable for that tick (fail closed). Unmanaged accounts
  are not touched. Event `relikey.account.credential_removed.v1`.
- The agent asks the bastion again within the same tick when a read fails transiently (a transport error, a 5xx
  or a 429): at most three reads, with a short doubling wait bounded by the tick and by shutdown. A short network or
  bastion hiccup no longer costs a tick; when every read fails, nothing is changed that tick (fail closed).
- Agent: idle ticks no longer rewrite the status files. `status.json`, `status.html` and `metrics.prom` are written
  when their content changes and otherwise at a 60 s heartbeat, so `updated` and
  `relikey_agent_status_updated_seconds` still tell a live agent from a stalled one; edge hardware often boots from
  flash. A bundle with a new serial but unchanged content is still stored: its serial and signed time are the replay
  floors (docs/agent.md). Tests and mutants cover both.
- The issue chooser's private-report link pointed to an owner that is not this project's; it now opens this
  repository's advisory form, and a test fails on any link to the repository under another owner. The issue
  templates are issue forms (What, Why, Done when, References) and apply labels that exist.

### Security
- The SBOM tool's `golang.org/x/crypto`, `x/net` and `x/text` are current, and each Go module's `go` line names
  Go 1.27.3, the release the code is built with, so dependency scanners no longer report advisories it already
  fixes. govulncheck finds nothing reachable in the agent or the fleet service, before and after.

## [0.1.2] - 2026-10-27

The first published release. It holds everything listed under 0.1.0 plus the fix below.

### Fixed
- The release build refused the v0.1.0 tag: release.yml runs on vX.Y.Z tags, `agent/build.py release` only took
  agent-vX.Y.Z. It now takes both, and a test ties it to the workflow's tag filter.

## [0.1.1] - 2026-10-27

Tagged and signed on the same commit as 0.1.0, before the fix above was merged, so its release build failed the same
way. Not released; the tag stays where it is.

## [0.1.0] - 2026-10-27

Tagged and signed, but not released: its release build failed (fixed in 0.1.2). Release tags are never moved, so the
tag stays where it is.

### Fixed
- A lease that went live before the desk knew its person's verified address never got its SSO credential: the agent
  took "no address" as final. It now asks again, no sooner than once a minute (full-stack run 8).

### Changed
- KeyClerk 0.26.3, pinned to its signed tag on github.com/keyclerk/keyclerk (cfc5793), the commit a public reader
  clones: the fixes of KeyClerk's 2026-10-26 review (approvals on leases, situations and surge packages are
  proof-checked) and the emSign CAs distrusted in its image. The core runs KeyClerk's YAML store, so the change-log
  steps of that release do not apply. The lab driver builds from a clone of the public repository.
- Warpgate 0.30.1 (security fixes upstream: the loopback IP check, web SSH through ticket sign-in, OIDC logout state
  stored sooner), pinned by digest in deploy/edge/compose.yaml and model/components.yaml.

### Added
- Decision 0027: from this release the public repository is the engine's source of record; every change is an
  issue and a pull request, and `tools/public_text_check.py` checks the text of each push, issue, pull request and
  comment (pre-push hook and the Public text workflow).
- The public repository's baseline: REUSE licensing (REUSE.toml, LICENSES/), ruff in CI, the Python tools hash-locked
  (requirements-ci.txt, requirements-test.txt), Dependabot for actions, Go modules and Python tools, OpenSSF
  Scorecard, a short fuzzing session per Go fuzz target in CI (FUZZING.md), a release workflow with reproducible
  binaries and a build provenance attestation, and the README's badge row. pyproject.toml now names the licence the
  code carries (EUPL-1.2; it said Apache-2.0).
- The fleet's anchor ceremony on the fleet page (decision 0026 points 16, 21, 30): the installer names at least three
  first officers (`--fleet-officers`); each registers a passkey for fleet statements and signs officer list version 1;
  with the last signature the fleet is anchored. WebAuthn registration in the in-house verifier, one small script
  allowed by its hash, Go and browser tests, fuzzing and mutants.
- Fleet enrolment wired (W1): the admin store (registry chain, slots, evidence log), the edge's POST
  /fleet/v1/enrol on the edge-facing name, and the page's Enrolment section opening slots and showing each code once.
- KeyClerk 0.26.1 pinned (signed tag aa29f6f: 0.26.0 with reproducible policy modules); its conformance vectors vendored with the 8 e-mail answers; the agent
  speaks edge protocol 1.3 (merged from feat/edge-protocol-1.3).
- The fleet's officer registry and enrolment, as tested building blocks (0026 points 14-33; not wired into the page
  or the installer yet): bound passkey statements checked in-house (ES256, EdDSA, RS256 over a CBOR decoder), the
  anchor and the versioned registry chain with its rules (two signatures, one device-bound, a majority to remove,
  48 hours or break-glass), slots and enrolment codes, the edge's presentation with proof of possession, and
  activation by one officer's passkey (typed 80-bit check, the reader recorded, relays read on site).
- Edge protocol 1.3 (KeyClerk 0.26.0): a lease's address leaves the bundle; the agent fetches it with a signed
  request (GET /api/v1/edge/lease/{id}/email), verifies the sealed answer (kc-edge-email-v1: pinned bundle key, this
  edge, this lease, this request's nonce) and sets the SSO credential. Once per live lease, in memory only: never in
  the state, the status or a log line. A lease's person is opaque (kc: anchors are not parsed).
- The fleet page (decision 0026 point 13): operators sign in at ReliKey's broker (code flow with PKCE, a client role
  `fleet-operator` on the fleet's own client) and see the inventory, read-only and without script, on its own name.
  `install.py --fleet-host`, `deploy/core/fleet_page.py --host|--grant`; back-channel logout honoured; the page
  reaches only the broker, through the front on the pod's loopback. In the fleet's own Go module (`fleet/`).
- Core install verifies KeyClerk's release tag: a pinned signer (`deploy/core/keyclerk.allowed_signers`) and the
  pinned commit.
- Role seams in the agent (decision 0023; 0016 accepted): the core speaks to a clerk and a bastion, not to KeyClerk
  and Warpgate. A neutral `bastion` package holds the role's model (accounts, roles reaching targets, expiring grants,
  identities, keys, sessions); Warpgate is the reference adapter; the clerk is whatever speaks the public edge protocol.
  A second, deliberately different bastion in the tests is driven to the same state by the same plan, and a test
  refuses any product import in the core.
- Crypto inventory and post-quantum transport (decision 0022 part A): `model/crypto.yaml` states what protects every
  link, format and trust anchor, each claim tied to the pinned version it was checked for; generated into
  `docs/reference/crypto.md` and a CycloneDX CBOM; the model check refuses a link without an entry or a stale claim.
  The agent requires hybrid X25519MLKEM768 on its links to the clerk and the bastion, refuses a classical peer and
  reports the negotiated group in status.json; the lab harness (kept with the maintainer) checks what each listener negotiates.
- The edge agent (Go): applies KeyClerk's signed leases on the edge and decides nothing. Built and tested with
  conformance vectors, mutation testing and fuzzing; an enrolment CLI; metrics.
- `deploy/core/`: the shared core as one composed pod (Caddy in front, Keycloak, KeyClerk, zot), with `install.py` and
  realm/SCIM wiring; a seed that can enrol an edge (a catalogue entry, a top group, an edge officer); passkey-only
  sign-in; approval proofs required and verified by the signer and the reconciler; health probes and a metrics
  listener. Proven end to end with an edge on rootful docker (the full-stack run).
- The agent applies visit leases (C-06): the visitor's SSH key and role for the signed window, removed at its end;
  only hardware-held or ed25519 keys; never a role reaching a target the visit does not name; the ceiling's visit
  rules enforced at the edge. Refused on a basic edge until hardware attestation lands.
- `deploy/edge/`: the edge pod (Warpgate, lldap, the agent) and `targets.py`, which creates the roles leases name, the
  targets and their pinned host keys.
- A vendor's own sign-in (decision 0018, proposed): `realm.py vendor` brokers a vendor's OpenID provider and
  `vendor-link` pins a person to their subject there; unlinked identities are denied, nothing is matched by e-mail or
  created, and the ReliKey passkey is still required after the vendor's sign-in.
- `adapters/` and decisions 0016-0017 (0017 accepted 2026-10-25, with a test-only second emitter in `agent/internal/testemit`): the contracts by role, and measuring adapters for Teleport and
  midPoint that show what is portable and what is ReliKey-specific.
- The model (`model/`): components, flows, patterns, contracts and open decisions as YAML, checked by
  `tools/check_model.py`.
- Decision records 0001-0015, including the core composition (0015), the sign-in gateway role (0014: part A accepted 2026-10-25, part B proposed) and HA
  per profile (0013).
- Community files: README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, issue and pull-request templates.

- Governed roles (full-stack run 2, finding 8): an account the agent does not manage that holds a role only leases
  grant is reported in the drift and never changed. The roles come from the edge's own targets file (`targets.py`
  writes `governed-roles.json`, a SCIM list of groups) and from `governed_roles` in the signed bundle (KeyClerk
  decision 0025); the agent governs the union. A malformed catalogue refuses the bundle; absent is never "none
  governed".
- The fleet service, first slice (decision 0026): `relikey-fleet` receives each edge's signed report (its own signing
  context, a rising sequence, a clock window), keeps the inventory (self-reported without a clerk; `unknown`, never
  last-known-good, for an edge that never reported), and raises the silence alarm as events. Loopback only. Slice 2: the
  agent sends its signed report every pull interval (`fleet.url`), the front routes that one POST, and the service
  is read-only towards edges by test; packaging in the core pod (R-21) follows.
- The agent long-polls the desk for its bundle (KeyClerk decision 0026, edge protocol 1.2): a grant or a revoke
  reaches the edge in seconds instead of within the pull interval; `long_poll_seconds` (default 55); a desk without
  long-poll answers at once and the pull interval stays the floor.
- Monitoring events from the edge agent (decision 0025 point 1): one JSON line per event, a CloudEvents 1.0
  envelope with OCSF 1.6.0 data (Account Change, User Access Management, Authentication, Compliance and Detection
  Findings) for each change the agent makes, an unmanaged account holding a governed role (once found, once gone), a
  refused bundle and an ended edge; the alert-event fields as extension attributes.
- Logons the bastion cannot carry (decision 0024): console servers with SSH per port for serial, a firmware update or a
  re-terminator in the zone for old TLS, and pattern P-F, a legacy client jump target, for telnet, rlogin, Java and
  KVM consoles; checklist items; no protocol code in ReliKey.
- The edge's install.py takes `--lab` (the edge pod on the host network beside a lab core); the README has a one-box
  lab quickstart.

### Changed
- The edge status page leads with who can reach what: a shift board, one row per live lease with a bar to when its
  access ends (eight hours ahead), coloured by class; the health state says what is wrong; the vitals are one line;
  notes are split into fixed by the agent and needing a person. The fleet page has the family look, dark mode, a
  summary line, silent edges first, releases behind, relative report ages (from the service's receive time) and a
  phone layout, under the same strict content policy. No assets, no script, no web fonts.
- `agent.json` is configured by role: the `keyclerk` section is `clerk`, the `warpgate` section is `bastion` with
  `"kind": "warpgate"`. A file with the old sections is refused with the rename it needs; status keys are
  `clerk_tls_group` and `bastion_tls_group`.
- Relicensed to EUPL-1.2 (was Apache-2.0), aligning with KeyClerk and the estate product class.

### Fixed
- Warpgate's admin paths are no longer published (decision 0008 point 1, stack attack E6): Warpgate's HTTPS listens on
  the pod's loopback (127.0.0.1:8899); a pinned Caddy front publishes 8888, refuses /@warpgate/admin*,
  /_warpgate/admin* and the self-service credential routes, and forwards the rest to Warpgate checked against its own
  certificate. The agent and targets.py use 8899. An edge installed before: re-run install.py (or set the bastion URL
  to 8899 and add the front).
- GUI red team (a review record kept with the maintainer): fleet report fields held to strict forms; the fleet's
  listeners answer loopback names only; outside text on the edge page shows invisible and direction
  characters as a mark; five fleet sessions per person; RFC 9207 iss checked; the edge page carries a CSP.
- A lease's role may no longer reach targets the lease does not name (AG-11, decided "agent enforces, fail closed",
  built until now only for visit leases): a role is assigned only if every target it reaches is named by the live
  leases granting it; a lease without a target is refused (stack attack E3: a taken-over desk could reach any target
  through a wider role).
- Edge install: Warpgate's built-in admin password goes through the environment, no longer the command line any local
  user can read (stack attack E2). `targets.py` sends the admin token only to the certificate install.py pinned
  (`deploy/secrets/warpgate.pin`), so a local user squatting 127.0.0.1:8888 gets nothing (E8), and prints the target
  key line with `restrict,pty`, so a lease cannot forward through the target (E9).
- An account the agent cannot read is closed and deleted when no live lease covers it, which needs no per-user read; a
  revocation whose session close fails still removes the role and SSO at once (stack attack 2026-10-25, E1, E5).
- The agent enforces the bastion settings ReliKey depends on, every tick, in enforce mode (reported in shadow mode):
  no self-service credentials, no password SSH, API tokens of at most an hour (`bastion.Hardener`; E1, E4).
- The fleet page: pending sign-ins sealed in the browser (a flood of visits cannot push one out), a stale sign-in
  refused, the client secret created 0600, the front restarted instead of an admin-API reload.
- The agent no longer closes an SSH session that is still signing in (waiting for the person's out-of-band
  approval): such a session has no user and no target yet, and a tick in that window cut the person off (full-stack
  run 2).
- The core's and the edge's install.py work when run by a normal user under rootful docker: the owners the containers
  need are set with the pinned busybox (they only printed a note before, and the front and the agent could not read
  their files). `targets.py` reads the admin token from warpgate.env when the agent's copy is not readable.

### Not yet done
- High availability, and the contracts still marked `needed` in the model.

# 0029: Signed updates, first slice: a vendor TUF root and an updater per edge profile

- Status: proposed (draft 3, 2026-11-07), for the maintainer's review
- Date: 2026-11-06
- Changes: 0026 points 2, 7, 8, 11 and 28 for this slice, as listed under Consequences: the repository alone decides
  until the director lands (a change of 0026 point 7's "installs only when both agree" until #33); the floor's
  definition; the updater on two edge profiles 0026 did not have (RHEL image mode and the Windows member server).
  Contract C-11: staging moves to #33, and the edge pins the update root's hash, not one key.
- Builds on: 0001 (a distribution), 0006 (working without a network), 0011 (the agent), 0026 (fleet management:
  signed, staged updates; Uptane's model on go-tuf v2; rollback outside the agent; the floor of point 28), 0028 (the
  spare), contract C-11
- Milestones: 0.4.0 (this slice), 0.5.0 (#33: the director in the bundle, staged rollout), 0.6.0 (#81: the Windows edge)
- Adversarial reviews: of draft 1 (keys, the missing director, offline expiry, the updater, the gate, consistency with
  0026) and of draft 2 (whose repository, the floor, what can be built). The records are kept with the maintainer.
  Draft 3 answers the second: points 1, 2 and 12 (whose repository), 5 (the floor), 7 and 8 (what is built).

## Context
0026 settled what signed updates are: a release is a manifest signed under release keys separate from the lease
key, naming images by digest and delivered through the core's mirror; the keys follow TUF roles with an offline root;
KeyClerk is the director that names each edge's release and floor in the signed bundle (Uptane's split), and the
agent installs a release only when the director and the repository agree; approving a release stays with the offline
release keys (point 19); an edge's floor is the highest of an offline-signed group floor, the clerk's minimum and its
installed release (point 28); rollback lives outside the agent (point 8). None of it is built.

Three things have changed since:
- **The order.** The maintainer placed C-11 in 0.4.0 and staged rollout (#33) in 0.5.0 (2026-11-06). KeyClerk's edge
  protocol carries a release manifest for policy modules (`kc-policy-release-v1`) but no director fields for edge
  releases, and KeyClerk 0.29.0 is not due before mid-December. A first slice has to stand without the director.
- **Two edge profiles 0026 did not have.** RHEL image mode (bootc, RHEL 9.6 and 10) gives transactional OS updates
  from a registry with rollback, and replaces rpm-ostree edge images in RHEL 10. The Windows edge (#81, 0.6.0) runs
  Warpgate and the agent as Windows services from a native installer.
- **The scenarios (2026-11-06).** A pilot's first question is how an update reaches an edge safely; the 112 centre
  needs updates per site and never both at once; a water utility's outstations are offline for hours or days and must
  not be bricked by expired metadata.

ReliKey is a distribution and each organisation runs its own core (0001). Who owns the update root for a
deployment's edges was open in draft 2. The maintainer decided (2026-11-07): one vendor root in this slice, a root per
deployment later, designed now so that it can be added without enrolling the edges again.

## Decision
1. **One vendor repository, mirrored by each core (0.4.0).** The maintainer publishes one TUF repository (root,
   targets, snapshot, timestamp) and the release artefacts. Each core pulls it outbound on a timer
   (`deploy/core/updates.py sync`), verifies it with go-tuf v2 against the vendor root it pins, copies the images it
   names from ghcr.io into its mirror (zot) by digest, and serves the metadata verbatim under its edge-facing name
   (`https://<edge-host>/updates/v1/`, a static path behind the front: `N.root.json`, `timestamp.json`,
   `snapshot.json`, `targets.json`, and `targets/` for installers). A core signs nothing: it can withhold or delay, not
   forge. An air-gapped core imports what `updates.py export` wrote on a connected host. Core updates are out of scope
   here.
   A target is one ReliKey release for one edge profile, with custom fields: `profile` (container, bootc, windows),
   `version`, `serial`, `requires_core` (the oldest core it runs with) and the digests (image digests, the bootc image
   digest, or the installer's SHA-256). `serial` is the release's integer, rising across profiles; when the director
   lands it is KeyClerk's `release.serial` for the same release. The updater refuses a target of another profile, and
   one whose `requires_core` is above the core it reaches (0026 point 11: never ahead; its "at most two releases
   behind" is reported, not enforced, in this slice).
2. **The keys, each with one job.**

   | Key | Held by | Online | Signs | The edge pins |
   |---|---|---|---|---|
   | update root | offline, threshold 2 of 3 PIV hardware tokens: two with the maintainer, one with the co-owner (0026 point 29) | no | the other update keys, their rotation | the root's hash, from its installer and in the signed updater binary |
   | update targets | offline, a PIV hardware token, with a backup token kept apart | no | the releases, the security floor, the revocations | through root |
   | update snapshot and timestamp | online, the maintainer's publishing job (never the release build job, never a core) | yes | freshness only | through root |
   | release tag key | the maintainer (`relikey.allowed_signers`), a passphrase-protected file in the password manager | not a hardware token | the git tag | nothing: never a TUF role |
   | KeyClerk's `release_key` | KeyClerk | KeyClerk's | policy modules (`kc-policy-release-v1`) | as today: never a TUF role |
   | cosign keyless identity | the release workflow | per run | binaries, images, SBOMs, attestations | nothing: checked at signing |
   | Authenticode (0.6.0) | the maintainer's code-signing certificate, on a hardware token (CA/Browser Forum rules) | no | the Windows installer | checked beside the TUF hash |

   The co-owner's root share is a PIV key on a hardware token, not the fleet officers' recovery passkey of 0026
   point 29: a passkey signs WebAuthn challenges, not TUF metadata. The signer is securesystemslib's hardware signer
   through the release tooling (point 3). The 2-of-3 root protects against losing a key and against one stolen token;
   with one maintainer it is not a separation of duties, and does not claim to be.
   **The residual of one vendor root, stated plainly:** whoever holds the targets token can sign a release that every
   edge of every deployment with automatic installs on will install. This slice limits it by keeping automatic installs
   off by default, switched on only at the edge (point 4), and by the per-deployment root that removes it (point 12).
3. **Signing a release is the maintainer's offline step, with one tool.** After the release build, the maintainer's
   signing tool verifies the release's keyless cosign signatures, its build attestation and its SBOM against ReliKey's
   release workflow, then signs the new targets with the offline token; one command re-signs targets without a
   release. Each core's `updates.py sync` verifies the same evidence again before serving it, as the second checker
   (0026 point 20). The edge trusts the TUF signatures, not a transparency log it may not reach. Prior art for the
   tooling: tuf-on-ci (sigstore's repository tooling: signing events with hardware keys, expiry handling).
4. **The director comes with KeyClerk (0.5.0, #33).** Until KeyClerk's bundle names each edge's release, the updater
   installs the newest target of its profile above its floor, and only when automatic installs are on. They are off by
   default and are switched on at the edge, by the site (the edge installer's `--auto-install`, in the updater's own
   configuration), never by the core, so a stolen core cannot turn them on. With them off, the site's operator starts
   each install with `relikey-update install`, which shows the target (version, serial, profile, digests, the root and
   targets versions that signed it, the floor, what restarts) and asks before it acts; it verifies everything the
   automatic path does. This slice is not a staged rollout and does not claim one: staging, canaries, the group freeze,
   0026 point 2's outside health gate and its group rollback command come with the director (0026 points 2, 10, 28).
5. **The floor (amends 0026 point 28 for this slice).** The updater keeps three things in its own state: the
   installed release, the floor, and the last release whose gate passed. The floor is the vendor's security floor in
   the targets metadata (later also the deployment's floor and the clerk's minimum); it never goes down, and it does
   not include the installed release. So KeyClerk's relay `rollback_release` range (floor <= serial < current) is not
   empty, and works as its reference does once the director lands.
   - Rollback after a failed gate returns to the last release that passed, when that release is at or above the
     floor.
   - When it is below the floor (the floor rose, and the release at the floor failed here), the updater does not go
     below it: it keeps the new release running, reports `update_gate_failed_at_floor` and alarms. The way out is
     signed: a revocation of the failing release.
   - The targets metadata carries revocations, signed offline: `{"serial": 12, "replacement": 11, "reason": "..."}`.
     The updater never installs a revoked serial; when it runs one, it moves to the replacement, even below the floor.
     The revocation entry is the signed downgrade, so a revoked floor release with nothing newer does not deadlock.
6. **Offline and expiry.** TUF refuses expired metadata. When the edge cannot refresh, the updater keeps the installed
   release running and installs nothing; it reports `update_metadata_stale` from the day the timestamp expires. An
   edge back online walks the root chain from the root it trusts to the newest, which TUF allows from an expired
   trusted root (only the final root's expiry is checked); the mirror keeps every root version.
   - Lifetimes: timestamp 7 days (an air-gapped core imports at least weekly, or its edges report stale), snapshot 7,
     targets 90 with a re-sign every 30, root 365. The publishing job alarms the maintainer when targets has 14 days
     left. A missed re-sign fails safe (stale, nothing installs), and the backup token covers a lost one.
   - Trusted time: go-tuf v2 checks expiry against the wall clock it reads at refresh, with no setting for another
     reference. The updater adds its own check on top: it persists the newest signed time it has seen (the latest
     timestamp's version and the time of its last good refresh) and refuses metadata older than that. Within one boot
     it also uses the boot clock, as the agent's clock package does. Across a reboot (every bootc update is one) a wall
     clock set back can still revive expired metadata for up to one expiry window; the persisted bound keeps it from
     going back to anything older than what the edge already trusted.
7. **An updater per profile (amends 0026 point 8).** The updater is separate from the agent, so a broken agent cannot
   block its own rollback, and it is split by privilege: an unprivileged fetcher runs go-tuf and downloads, and writes
   a request (profile, serial) into a spool directory; a minimal privileged unit acts only on that request. The
   privileged unit verifies the cached metadata itself from the pinned root and hashes the artefacts itself before it
   acts, so a compromised fetcher can make it refuse, never install.
   - **State and report, every profile.** The state is one versioned JSON file (`schema_version`; a release reads the
     state of the release before it and writes a form that release can still read), in `/var/lib/relikey-update` on
     bootc and rootful hosts, `$XDG_STATE_HOME/relikey-update` under rootless podman, and `%ProgramData%` on Windows.
     The updater writes `update-status.json` where the agent reads it, and the agent carries it in its signed fleet
     report: root, targets and snapshot versions, timestamp expiry, installed serial, floor, last passed serial,
     pending serial, rejected serials, last good refresh, stale, automatic installs on or off.
   - **Container edge (podman compose, as the edge runs today):** the privileged unit is a systemd unit of the user
     who owns the pod. It writes the verified digests into `deploy/edge/release.env`, which `compose.yaml` reads for
     each image, recreates the services with `compose up -d`, runs the gate, and writes back the last good digests
     when it fails. The last good images are kept locally and never pruned, so a rollback needs no mirror. Moving the
     edge to quadlet units is a separate decision.
   - **RHEL image mode (bootc), the appliance profile:** the release is a bootc image whose pod images are logically
     bound images (pulled with the OS image, so a booted release has its pod). The privileged unit runs `bootc switch`
     to the verified digest; a deny-by-default `/etc/containers/policy.json` is what checks the image signature, and
     `--enforce-container-sigpolicy` makes bootc refuse a permissive policy. greenboot's boot counting rolls back an
     image that never boots (to confirm on the lab box that it drives `bootc rollback` on image mode with GRUB before
     0.4.0); the gate rolls back one that boots but fails. The updater's and the agent's state live in `/var`, never
     `/etc`, because `bootc rollback` restores the old deployment's `/etc`. The bootc update timer stays masked. RAUC
     stays for appliances whose OS is not RHEL.
   - **Windows member server (0.6.0):** the fetcher copies the installer into an updater-owned, ACL-locked directory;
     the privileged service checks the TUF hash and the Authenticode signature on that copy itself, installs side by
     side, switches the services, runs the gate and switches back when it fails. Details in #81's decision record.
   - **The updater itself** is a target of its own. A new updater commits only after a self-check (one successful
     refresh and verification with the new binary), keeps its previous binary, and goes back to it when the self-check
     fails; on bootc it ships inside the OS image. The agent's gate does not test the updater.
   - **A rejected release** is remembered by serial: after a rollback the updater does not try it again, only a newer
     target or a revocation's replacement.
8. **The gate checks availability, not intent.** A malicious release can report itself healthy; the gate stops a
   broken release, never a hostile one, and does not claim to. Hostile releases are stopped at signing (point 3) and
   by revocation (point 5). The gate passes when the new release starts, reports a status that verifies and applies
   its bundle within ten minutes. When the agent cannot reach the desk, the updater probes the desk itself: if it gets
   through and the agent does not, the gate fails; if neither does, the update holds (the new release keeps running,
   so a desk outage never rolls back a security fix). While the desk is unreachable, early revocations wait for it,
   with or without an update; Warpgate still expires grants on its own. The updater reports any agent outage longer
   than five minutes.
9. **A freeze is bounded and reported.** A core signs nothing, so it cannot serve fresh timestamps over old targets:
   holding an edge back is bounded by the timestamp's 7 days, after which the edge reports stale. Each edge reports
   the targets version it trusts; the maintainer publishes the current one with each release; the external dead-man
   check (0026 point 12) compares them and alarms on an edge more than one version behind for a day. Residual: the
   reports reach the external check through the core's fleet service, so a stolen core can also withhold them; the
   check then sees silence, which 0026 point 12 alarms on. Edges the fleet marks `offline_expected` (the water
   utility's outstations) alarm only past their own window.
10. **Two nodes and one.** On a two-node edge (0028) the spare updates first, in shadow mode. Since a shadow node
    applies nothing, its gate proves the release starts and verifies, not the write path. 0028 has no path for the two
    nodes to coordinate, so in this slice the site's operator updates the active node after the spare reports a passed
    gate; automatic ordering comes with the director. A `promote` during an update aborts the update on that node and
    returns it to its last good release: takeover is never blocked. A single-node edge updates in a window the site
    sets; automatic installs stay off by default, as point 4.
11. **The first root.** The edge learns the update root's hash from its installer (`--update-root`), and the signed
    updater binary carries the same hash: on a mismatch the updater refuses to start. Since the installer's values come
    from the deployment's own core, this is still trust in that core at install, not trust on first use from the mirror
    later. The lab and the demo use their own root, which production never trusts.
12. **A root per deployment, later, without enrolling again.** The edge installer also takes an optional deployment
    update anchor (`--deployment-update-anchor`: the public key of a hardware token the deployment's owner holds),
    which the updater pins and does not use in this slice. When the per-deployment slice lands, a deployment root
    signed by that anchor becomes the edge's root; it delegates releases to the vendor's targets key, and signs the
    deployment's own floors, groups and revocations, so no vendor key alone reaches its edges. An edge installed
    without the anchor needs a site visit to gain it, because any in-band change would be signed by the vendor keys it
    is meant to limit.

## Consequences
- 0.4.0 can ship signed updates without KeyClerk: the vendor repository and its sync to each core, the offline keys,
  the floor and revocation, the container updater and its gate. The bootc updater lands with the RHEL appliance
  profile; the Windows updater with #81.
- For this slice, 0026 changes in these points: point 7 (the repository alone decides until the director), point 28
  (the floor excludes the installed release; revocations carry their replacement), point 2 (the outside health gate
  and group rollback wait for #33), point 8 (the updater per profile), point 11 ("two releases behind" reported, not
  enforced).
- The maintainer gains the root ceremony (three PIV tokens, one with the co-owner), a targets signature per release
  and every 30 days, a backup targets token, and the publishing job's online key. The release guide says how.
- Every deployment shares the vendor root until point 12 lands; automatic installs are off unless a site turns them on.
- Until the director, updates are not staged per site: deployments that need that keep automatic installs off.
  C-11's "rollout is staged by edge group" moves to #33, and its "pins its public key" becomes "pins the update root's
  hash" when this is accepted.
- The model gains `updates.py sync` on the core, the static update path behind the front, the updater on each edge,
  and the keys above.

## Prior art
TUF specification 1.0 (roles, thresholds, expiry, the root chain from an expired trusted root; freeze bounded only by
expiry) and go-tuf v2 (Apache-2.0; expiry checked against the wall clock at refresh). TUF delegations (a deployment
root delegating releases to a vendor key, as point 12). Uptane (director and image repository; its client is dormant,
0026). tuf-on-ci (sigstore's repository tooling). RHEL image mode: `bootc switch`, `--enforce-container-sigpolicy`
refusing a permissive policy, `bootc rollback` restoring `/etc`, logically bound images, the masked
`bootc-fetch-apply-updates.timer`; greenboot boot counting. RAUC with boot counting (0026). podman auto-update (a
`local` policy and rollback, but by tag and verifying nothing ReliKey signs). Teleport managed updates (canaries,
rollback on a failed health check; unsigned binaries, 0026). Notary v1 (TUF for images, retired) and Notation (signs,
without TUF's freshness). sigstore's use of TUF for its own trust root.

## Changelog
- 2026-11-06: draft 1; adversarial review: the targets key's place, three keys called "release key", the site-key
  re-anchoring (wrong and unneeded: TUF's root chain handles an expired root), the floor against rollback, the
  updater's privilege and its own update, bootc's `/etc` and boot counting, the gate as availability only, a targeted
  freeze, the first root. Draft 2 answers each.
- 2026-11-07: draft 3, after the review of draft 2 and the maintainer's decision on the root (one vendor root now, a
  root per deployment later): the core mirrors and signs nothing; automatic installs off by default, switched on at
  the edge; the deployment anchor pinned now (point 12); the floor excludes the installed release and revocations name
  their replacement; what is built per profile (compose, the update path, sync, state, report fields, the install
  command); the privileged unit verifies itself; the gate probes the desk; trusted time across a reboot stated
  honestly; bootc's signature policy, greenboot and bound images; the updater's self-check; promote aborts an update;
  PIV tokens, a backup targets token, targets 90 days with a 30-day re-sign; a shorter title.

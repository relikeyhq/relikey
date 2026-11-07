# 0029: Signed updates, the first slice: a TUF repository, offline release keys, and an updater per edge profile

- Status: proposed (draft 2, 2026-11-06, after an adversarial review of draft 1), for the maintainer's review
- Date: 2026-11-06
- Changes: 0026 points 2, 7, 8 and 28 (the order of building them; key rotation through TUF's root instead of the
  bundle until the director lands; the updater on two edge profiles 0026 did not have: RHEL image mode and the Windows
  member server); contract C-11 (staging moves to #33). Nothing in 0026's intent.
- Builds on: 0001 (a distribution), 0006 (working without a network), 0011 (the agent), 0026 (fleet management:
  signed, staged updates; Uptane's model on go-tuf v2; rollback outside the agent; the floor of point 28), 0028 (the
  spare), contract C-11
- Milestones: 0.4.0 (this slice), 0.5.0 (#33: the director in the bundle, staged rollout), 0.6.0 (#81: the Windows edge)
- Adversarial review (draft 1): keys, the missing director, offline expiry, the updater, the gate, consistency with 0026; the
  record is kept with the maintainer. Its five main findings are answered in points 2, 5, 3, 6 and 9 below.

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

## Decision
1. **The repository first (0.4.0).** The core serves TUF metadata (root, targets, snapshot, timestamp) beside the
   images, verified with go-tuf v2 (0026 point 7). A target is one ReliKey release for one edge profile, with custom
   fields: `profile` (container, bootc, windows), `version`, `serial`, `requires_core` (the oldest core it runs with)
   and the digests (image digests, the bootc image digest, or the installer's SHA-256). The updater refuses a target
   of another profile, and one whose `requires_core` is above the core it reaches (0026 point 11: never ahead).
2. **The keys, each with one job.**

   | Key | Held by | Online | Signs | The edge pins |
   |---|---|---|---|---|
   | update root | offline, threshold 2 of 3: two maintainer hardware tokens and the co-owner's hardware key (0026 point 29) | no | the other update keys, their rotation | the root hash, from enrolment |
   | update targets | offline, a maintainer hardware token | no | the targets: each release, the group floors, the revoked serials | through root |
   | update snapshot and timestamp | online, in a `tuf` container of the core pod, never the fleet service | yes | freshness only | through root |
   | release tag key | the maintainer (`relikey.allowed_signers`) | no | the git tag | nothing: never a TUF role |
   | KeyClerk's `release_key` | KeyClerk | KeyClerk's | policy modules (`kc-policy-release-v1`) | as today: never a TUF role |
   | cosign keyless identity | the release workflow | per run | binaries, images, SBOMs, attestations | nothing: checked at signing |
   | Authenticode (0.6.0) | the maintainer's code-signing certificate | no | the Windows installer | checked beside the TUF hash |

   The 2-of-3 root protects against losing a key and against one stolen token; with one maintainer it is not a
   separation of duties, and does not claim to be. A stolen core can sign freshness, never a release (0026 point 19).
3. **Signing a release is the maintainer's offline step.** After the release build, the maintainer's signing tool
   verifies the release's keyless cosign signatures, its build attestation and its SBOM against ReliKey's release
   workflow, then signs the new targets with the offline key and uploads the metadata. The core verifies the same
   evidence again before serving it, as the second checker (0026 point 20). The edge trusts the TUF signatures, not a
   transparency log it may not reach.
4. **The director comes with KeyClerk (0.5.0, #33).** Until KeyClerk's bundle names each edge's release, the updater
   installs the newest target of its profile at or above its floor. This slice is therefore not a staged rollout and
   does not claim one: one core serves every edge, so a release reaches every edge of a profile. Until the director,
   a deployment that needs updates per site (the 112 centre) runs with automatic installs off, and the site's operator
   starts each install by hand (`relikey-update install`), which still verifies everything. Staging, canaries and the
   group freeze come with the director (0026 points 2, 10, 28).
5. **The floor (amends 0026 point 28 for this slice).** The updater keeps two numbers in its own state: the installed
   release and the floor. The floor is the highest of the offline-signed group floor in the targets metadata and the
   highest release whose gate passed on this edge; it never goes down. Rollback after a failed gate returns to the
   last release that passed, which is at the floor by construction. The targets metadata also carries the revoked
   serials, signed offline: the updater never installs one and, when it runs one, moves to the newest release that
   is not revoked; going below the floor takes an offline-signed downgrade statement naming the edge group and the
   serial (0026 point 2). The clerk's minimum joins the floor with the director, and KeyClerk's relay
   `rollback_release` then works within it as its own reference already does.
6. **Offline and expiry.** TUF refuses expired metadata. When the edge cannot refresh, the updater keeps the installed
   release running and installs nothing; it reports `update_metadata_stale` from the day the timestamp expires. An
   edge back online walks the root chain from the root it trusts to the newest, which TUF allows from an expired
   trusted root (only the final root's expiry is checked); the mirror keeps every root version. Lifetimes: timestamp
   1 day, snapshot 7, targets 30, root 365; the maintainer re-signs targets every 14 days. The updater keeps its own
   trusted time (its last good refresh, with the boot clock, as the agent's clock package does), so a wall clock set
   back cannot revive expired metadata; it does not rely on the agent, which it may be replacing.
7. **An updater per profile (amends 0026 point 8).** The updater is separate from the agent, so a broken agent cannot
   block its own rollback, and it is split by privilege: an unprivileged fetcher runs go-tuf, downloads and verifies,
   and writes one verified request (profile, serial, digests) into a spool directory; a minimal privileged unit acts
   only on that request, checks it against the fetcher's verified metadata digest, and does nothing else.
   - **Container edge (podman):** the privileged unit writes the verified digests into the pod's quadlet drop-in,
     restarts the units, runs the gate, and switches back to the last good digests when it fails. The last good
     images are kept locally and never pruned, so a rollback needs no mirror.
   - **RHEL image mode (bootc), the appliance profile:** the release is a bootc image; the privileged unit runs
     `bootc switch --enforce-container-sigpolicy` to the verified digest, with a deny-by-default `policy.json` as a
     second layer, then reboots. Boot counting (greenboot, or systemd's boot assessment) rolls back an image that
     never boots; the gate rolls back one that boots but fails. The updater's state, the agent's floors and serials
     live in `/var`, never `/etc`, because `bootc rollback` restores the old deployment's `/etc`. The bootc update
     timer stays masked. RAUC stays for appliances whose OS is not RHEL.
   - **Windows member server (0.6.0):** the fetcher copies the installer into an updater-owned, ACL-locked directory,
     checks the TUF hash and the Authenticode signature on that copy, and the privileged service installs side by
     side, switches the services, runs the gate and switches back when it fails. Details in #81's decision record.
   - **The updater itself** is a target of its own. It is updated only after the agent's gate on the same release
     passed, keeps its previous binary, and on bootc ships inside the OS image.
   - **A rejected release** is remembered by serial: after a rollback the updater does not try it again, only a newer
     target.
8. **The gate checks availability, not intent.** A malicious release can report itself healthy; the gate stops a
   broken release, never a hostile one, and does not claim to. Hostile releases are stopped at signing (point 3) and
   by revocation (point 5). The gate passes when the new release starts, reports a status that verifies and applies
   its bundle within ten minutes. An unreachable desk is a hold, not a failure: the updater waits and keeps the new
   release, so a desk outage never rolls back a security fix. While the agent is down for an update, Warpgate still
   expires grants on its own, but early revocations wait; the updater reports any agent outage longer than five
   minutes.
9. **A targeted freeze is detected, not only bounded.** A stolen core could keep one edge on an old, unrevoked
   release by serving it fresh timestamps over old targets until targets expire. Each edge reports the targets
   version it trusts; the maintainer publishes the current targets version with each release; the external dead-man
   check (0026 point 12) compares them and alarms on an edge more than one version behind for a day.
10. **Two nodes and one.** On a two-node edge (0028) the spare updates first, in shadow mode. Since a shadow node
    applies nothing, its gate proves the release starts and verifies, not the write path. The active node updates
    only after the spare's gate passed; `promote` is refused on a node whose update is in progress. A single-node
    edge updates in a window the site sets (default: automatic installs off, as point 4).
11. **The first root.** The edge learns the update root's hash from its enrolment, with the fleet's address and pin
    (0026 point 18); it never trusts a root on first use from the mirror. The lab and the demo use their own root,
    which production never trusts.

## Consequences
- 0.4.0 can ship signed updates without KeyClerk: the repository, the offline keys, the floor and revocation, the
  container updater and its gate. The bootc updater lands with the RHEL appliance profile; the Windows updater with #81.
- The maintainer gains two ceremonies: the root (three hardware keys, one with the co-owner) and a targets signature
  per release and every 14 days. The release guide says how.
- Until the director, updates are not staged per site: deployments that need that run with automatic installs off.
  C-11's "rollout is staged by edge group" is moved to #33.
- The model gains the `tuf` container in the core pod, the updater on each edge, and the keys above.

## Prior art
TUF specification 1.0 (roles, thresholds, expiry, the root chain from an expired trusted root; freeze bounded only by
expiry) and go-tuf v2 (Apache-2.0). Uptane (director and image repository; its client is dormant, 0026). RHEL image
mode: `bootc switch --enforce-container-sigpolicy`, `bootc rollback` restoring `/etc`, the masked
`bootc-fetch-apply-updates.timer`; greenboot boot counting. RAUC with boot counting (0026). podman auto-update (a
`local` policy and rollback, but by tag and verifying nothing ReliKey signs). Teleport managed updates (canaries,
rollback on a failed health check; unsigned binaries, 0026). Notary v1 (TUF for images, retired) and Notation (signs,
without TUF's freshness). sigstore's use of TUF for its own trust root.

## Changelog
- 2026-11-06: draft 1; adversarial review: the targets key's place, three keys called "release key", the site-key re-anchoring
  (wrong and unneeded: TUF's root chain handles an expired root), the floor against rollback, the updater's privilege
  and its own update, bootc's `/etc` and boot counting, the gate as availability only, a targeted freeze, the first
  root. Draft 2 answers each.

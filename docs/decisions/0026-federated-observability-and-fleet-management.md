# 0026: Federated observability and fleet management: ReliKey's own, tiered, tighten-only below the parent

- Status: accepted (operator, 2026-10-25), draft 2 after its red team, on the operator's condition that KeyClerk 0027
  take the red team in (2fa2e25, 4205d60). Nothing built yet.
- Build state (2026-10-29): the line above was true when accepted; what is built since is in "Build state" below.
- Date: 2026-10-25
- Builds on: 0005 (a small edge and a shared core), 0006 (working without a network), 0013 (the witness on site, the
  break-glass promotion), 0021 (no telemetry relay), 0023 (role seams), 0025 (the trust sensor and its evidence log);
  KeyClerk 0013 D3 (nested child KeyClerk) and 0027 (relay certificates, the provisional statement)

## Context
A production ReliKey deployment has many edges, often on sites that lose their uplink. Every serious agent fleet has
an inventory, health and a silence alarm, signed and staged updates with rollback, and a way to govern versions;
ReliKey's own claims (a revoke in seconds, silence is an alarm) cannot be shown without them. The edges already
produce what a fleet view needs: `status.json`, `metrics.prom`, the events of 0025, the applied serial, drift, the
version and the last pull. Prior art (2026-10-25): Teleport's managed updates group agents with canaries and roll back
on a failed health check, but ship unsigned binaries, which staged rollout does not replace; SPIRE enrols with a
single-use token and rotates on its own; Elastic's tamper protection is defence in depth, not protection from a local
administrator.

## Decision
1. **Fleet management is ReliKey's own.** A fleet service in the core holds, per edge: last seen, the release it runs,
   applied serial, drift, attested profile, link crypto as the agent reports it, and the silence alarm (no report for
   N pull intervals). It works with any clerk or none: no clerk can be assumed present. When a clerk is present it adds
   its governance facts: for KeyClerk, the leases and serials issued against those applied (the omission cross-check
   of 0025 point 3), relay tightenings in force, provisional replacements and evidence. Without a clerk the view is labelled
   **self-reported, not attested**, and only bad news from it counts (0025 point 3). An edge behind a silent relay
   shows as "unknown, last verified at T", never as last-known-good. Device telemetry (hardware
   health, resource use) stays in the organisation's OpenTelemetry (0021); the fleet service carries evidence and
   governance events only.
2. **Updates are signed and staged.** A release is a signed manifest under a release key separate from the lease key
   (C-11), naming images by digest, delivered through the core's zot mirror. Rollout by group, with canaries first
   (shadow mode, then enforce), a health gate after each update (the agent's own `status` check), automatic rollback on
   the edge when the gate fails, and a group rollback command. A minimum release per group travels in the signed bundle
   or ceiling, and **the edge enforces it**: it keeps the minimum release with its floors and refuses anything older,
   unless a release-key downgrade statement names the move. Release keys follow TUF roles (an offline root, threshold
   signing, expiring timestamp metadata against a withheld-manifest freeze, rotation and revocation carried in the
   bundle). The health gate is not only the agent's own check: the core also checks from outside (heartbeat, chain
   continuity, the serial applied), picks the canaries and holds a soak time. The edge never runs an unsigned binary.
3. **The enrolment key rotates.** The agent rotates its enrolment key through the clerk's rotation (KeyClerk
   `rotate_edge`), co-signed as at enrolment.
4. **Tiers, recursive, at most three below the parent.** The same software at every level; each level narrower than
   the one above. A site tier depends on the site's profile:
   - by default a **site relay**: the fleet view and an event store for its subtree, with store-and-forward upward so
     the parent backfills after an outage; a cache of the last signed bundles and releases; the witness (0013);
   - a **full site core** (broker and clerk) only for sites the profile marks as long-isolated (KeyClerk 0013 D3,
     nested child KeyClerk, planned for its 0.30.0; relays until then).
   Each level witnesses its children's chain heads (0025 point 2) and the parent re-witnesses them on reconnect.
5. **Below the parent, a relay only tightens.** While its parent is down a relay may, for its subtree only: revoke a
   lease, end a lease earlier, cut sessions, end an edge, roll back to an earlier signed release, hold at the current
   release. It does so under a relay certificate the edge officer signs with their hardware key, naming the relay's
   key, its subtree, an expiry and those operations (KeyClerk 0027, `kc-edge-relay-v1`, `kc-edge-tighten-v1`). The edge
   verifies the chain from its pinned officer key, applies only what narrows its current state, and keeps a tightening
   until a newer parent serial: each tightening names the parent serial it
   applies against and carries a relay counter that only rises, so a future-dated or replayed tightening cannot outlive
   the parent, and it lapses when the certificate expires in trusted time (0025). A rollback goes no lower than the
   minimum release; a hold cannot keep an edge below it, expires with the certificate and raises an alarm. An end a
   relay orders is a suspension a parent bundle can lift, so a stolen relay key cannot force re-enrolment. The officer
   signs every relay certificate directly (no delegation below), subtrees list edge ids, and expiries are short. An
   edge flags a relay serving a serial older than the parent's newest, and the fleet view compares the two, since
   withholding a revoke widens access by omission. Bounded, not prevented (KeyClerk 0027): the edge detects a relay
   serving a bundle older than one it holds (its serial floor) and a parent gone quiet (the horizon), but cannot see a
   newer parent bundle a relay hides; a withheld revocation lasts at most until its class's horizon ends (1 hour for
   privileged), when those leases stop being live anyway. That window is a stated residual. A relay passes on what the parent already signed and it holds; it never
   grants, releases a new version or widens.
6. **One break-glass up-move: replacing a dead edge on site.** The site's physical key (one per site, enrolled at the
   desk like an officer key and pinned in each edge's enrolment) and the new node sign a "provisional" statement naming
   the dead edge's id and the new node's enrolment key. The relay serves the cached bundle for that id only to that key,
   so the replacement has the dead edge's slot, ceiling and targets by construction, never wider. It is logged on site
   and shown on the status page, ends with the cached bundle's horizon, and on reconnect the officer confirms it (the
   rotation statement) or ends it (the ended notice). 0013's break-glass promotion uses the same key. The relay accepts a replacement
   only after the dead edge has been silent for a stated period, and at most one provisional replacement per edge id;
   if the original id reports again, both are frozen until the officer decides. A provisional key never receives a
   refreshed bundle, so the officer's end applies at the next one. The site key needs a PIN or presence, labels each use
   (replacement, promotion) separately, and its uses are counted on the status page.

## Amendment, 2026-10-25 (operator, decide loop on verified prior art)
7. **Releases follow Uptane's model on go-tuf v2.** The clerk is the director: it names each edge's release and floor
   in the signed bundle. The image repository is the TUF-signed release manifest in the zot mirror. The agent installs a
   release only when both agree. Not Uptane's own client, dormant since its last release in February 2020; go-tuf v2 is
   maintained and Apache-2.0.
8. **Rollback lives outside the agent, by profile.** An agent cannot roll itself back. On every edge a minimal updater
   keeps the agent's last good image digest and switches back when the health gate fails; on appliances whose OS
   ReliKey images, RAUC's A/B slots with bootloader boot counting (a separate process, LGPL-2.1).
9. **The fleet service is read-only towards edges**, a tested invariant: it receives reports and commands nothing;
   every change reaches an edge only as a signed bundle or a signed release (the Kaseya VSA attack of 2021 and the
   SolarWinds Orion compromise of 2020 went through fleet tooling).
10. **Rollout guards:** jittered reconnects after a core or desk outage, so edges do not return all at once; a cap on
    edges changed per minute; one global freeze that halts every rollout.
11. **Version skew:** an agent may run up to two releases behind the core and the clerk, never ahead; CI tests the
    agent's two previous releases against the current core, and the minimum release forces urgent updates.
12. **The fleet service is watched from outside:** an external dead-man check alarms when it goes quiet.

13. **The fleet page, behind the broker** (operator, decide loop 2026-10-25). Operators see the fleet on a page of its
    own, not by tunnel:
    - *its own name:* an optional fourth name on the front (`FLEET_HOST`), never the desk's name, which is the clerk's,
      so the page works with no clerk; the edge-facing name keeps serving only the report route;
    - *sign-in at ReliKey's broker:* the fleet service is a confidential OIDC client of the broker, code flow with
      PKCE and an ID token checked for issuer, audience, authorised party and nonce, like each Warpgate (0010); a
      *client* role `fleet-operator` on the fleet's own client admits (granted by the broker's admin or the clerk's
      governance; no realm role, so no default-roles path grants it); a passkey at the broker, nothing verified by the
      fleet itself (0001 point 5);
    - *a session that is short and narrow:* a pre-sign-in cookie binds state, nonce and the PKCE verifier to the
      browser that started; a fresh opaque session id after sign-in, in a `__Host-` cookie (`HttpOnly`, `Secure`,
      `SameSite=Lax` for the callback, then checked on every request), 15 minutes; back-channel logout from the broker
      honoured on a route only the pod reaches;
    - *read-only and plain:* the page shows the inventory and its basis ("self-reported, not attested" without a
      clerk), offers no action on any edge (point 9), sends a strict content security policy and no script;
    - *in process, on its own port* (red team and decide loop, 2026-10-25): the fleet service carries the OIDC client
      itself (`go-oidc`, `x/oauth2`, pinned), in its own Go module so the edge agent's dependencies never grow; the
      page listens on its own loopback port, and the front proxies only `/`, `/callback` and `/logout` on
      `FLEET_HOST` to it. The JSON stays on loopback; silence events go to the organisation's monitoring.

- A deployment without KeyClerk still has fleet management; with KeyClerk it also has the governance facts.
- Residual: a stolen relay key can deny service to its subtree (revoke everything), bounded by the certificate's
  expiry and subtree. A stolen site physical key can stand up a replacement for a dead edge, bounded by that edge's
  cached bundle and horizon, and visible on the status page until the officer acts.
- Every level adds a hop for upward data and a point that can lag; the depth cap bounds it.
- A relay's backfill is trusted only for records the edge signed whose heads chain to the last witnessed head; what a
  relay alone witnessed is advisory until the parent witnesses it again. Until the evidence log (C-12, C-13) exists,
  backfill is unverified.
- Not built (when accepted): the fleet service, the relay, signed releases and staged rollout, enrolment-key rotation
  on the agent. Since then the fleet service is built; see "Build state".

## Amendment, 2026-10-25 (operator, decide loop on fleet administration and enrolment)
The operator: everything is done through the admin GUI and nobody runs a script; the fleet updates its edges; edges
are enrolled into their first-in-line fleet. KeyClerk is just a clerk, replaceable by any IGA. The GUI red team
(a review record kept with the maintainer) set the constraints.

14. **The fleet server holds no authority; the GUI does everything** (D1). Point 9 stands: the fleet commands no edge.
    The GUI covers every task, but a change that increases exposure takes effect only through people's signatures:
    an edge's enrolment needs one officer's passkey (point 15), a change to the officer registry two (point 16), a
    release the offline release keys (point 7). Changes that reduce exposure take effect with a GUI session alone:
    freezing rollouts, decommissioning an edge (its reports are no longer accepted), issuing an enrolment code. A stolen
    session drafts and freezes; it cannot admit or release. Point 13's "read-only, no action" is amended accordingly:
    the page shows actions, and each says which signatures it needs.
15. **Enrolment into the fleet** (D2): the GUI opens a slot (name, profile, 24 hours) and gives a one-time enrolment
    code naming the fleet's address, its certificate pin, the slot and a single-use secret. The installer takes only
    the code, generates the edge's key on the box (later in its TPM), presents the public key with proof of the secret
    on one POST route on the edge-facing name (capped and rate-limited, like the report route), and prints the key's
    fingerprint on the edge's screen. The approver sees the name, the source address and the fingerprint, types the
    fingerprint's last characters as read from the edge's screen (no tap-to-approve: device-code phishing, Storm-2372),
    and activates with one officer's passkey; several slots may be activated in one signed statement. A second key for
    a used slot, or a mismatch, is shown and logged, never silently replaced. Fleet membership grants nothing on a
    site: access to targets stays the clerk's own co-signed enrolment.
16. **The officer registry** (D3): the installer pins the first officers' passkeys as the anchor. Every later change
    is the whole new registry signed by two existing officers' passkeys, and the fleet verifies the chain back to the
    anchor. The fleet server holds no key that can add an approver. Residual: with fewer than two working officer
    devices the registry cannot change and is re-anchored by a reinstall (passkeys synced in a password manager; more
    than two officers).
17. **A clerk's part** (D4): the fleet owns enrolment and its registry in every deployment. A clerk (KeyClerk or any
    IGA) may add facts only through a published, clerk-neutral contract, as the edge protocol is: a signed roster of
    enrolled edges and their keys, and approvals. No KeyClerk-specific feed; KeyClerk never hosts the fleet. Point 7 is
    amended to match: the Uptane director (which release each edge should run) is the fleet's role, choosing only among
    releases the offline keys signed; a clerk may add a minimum release through the same contract.
18. **Finding the fleet** (D5): the enrolment code always names the fleet (address and pin). No DNS discovery for now;
    a signed SRV record can be added if mass rollouts need it.
19. **Rollouts in the GUI** (D6): pace and freeze in the GUI (point 10's guards); approving a release stays with the
    offline release keys (point 7). The GUI shows the rollout, never signs it.

### After the red team of points 14-19 (2026-10-25; a review record kept with the maintainer)
Straight tightenings, taken in:
20. **The fleet is never the only checker.** Every signed statement (an activation, a registry, a director choice) is
    checked by a party other than the fleet server as well: the edge for anything that changes what it runs, the parent
    fleet for a child's roster, the clerk for its roster. The fleet stores and forwards statements. A statement no one
    else checks grants nothing beyond the fleet's own display. (Points 14-17 read with this; TUF: the client checks.)
    Note, 2026-10-28 (operator, for release 0.2.0): an activation is checked by the fleet alone for now. It changes
    only the fleet's display and which reports the fleet accepts, never what an edge runs; the signed activation is in
    the evidence log, where an auditor can verify it again. A second live checker, the clerk checking its roster,
    follows with the end-to-end work (#23).
21. **A passkey signs a bound statement, not a page.** The challenge is H("relikey-fleet-stmt-v1" || the canonical
    statement), and the statement names the fleet id, the registry version, an expiry and a nonce. The checker
    requires type webauthn.get, the exact origin of FLEET_HOST, the rpId of a statement credential registered
    separately from broker sign-in credentials, and user verification (UV), and keeps clientDataJSON and
    authenticatorData with the statement. Every statement expires.
22. **Decommissioning is a request, not a quiet removal.** A decommissioned edge stays watched as "decommissioning",
    and its silence still alarms, until the clerk (or, without one, an officer's statement) confirms its site enrolment
    has ended; one that reports again alarms. Bulk decommission needs an officer's passkey. An edge removed from the
    configuration is shown as removed, not dropped silently.
23. **A freeze set by a session expires** (24 hours), alarms every officer and records who set it and why; extending
    it needs an officer's passkey. The edge-enforced minimum release is never frozen.
24. **Enrolment, tightened:** the typed check is at least 16 base32 characters (80 bits) or the whole fingerprint as a
    word list; the edge shows its fingerprint only after presenting, and shows "slot already taken" when refused; the
    presentation proves possession (the edge's key signs the fleet id, the slot and the secret's commitment); a batch
    needs the typed check for every slot and holds at most ten; open slots are capped per fleet and per operator, and
    each shows who opened it and when; the code travels as a QR code or on a USB stick, not typed.
25. **A clerk's facts are bounded:** the clerk's contract key is admitted to the registry by two officers; a clerk's
    approval counts as at most one signature; a clerk's minimum release must name an offline-signed release (otherwise
    the edge ignores it and alarms) and is paced by the rollout guards unless the offline keys marked the release
    urgent; a roster that disagrees with the fleet's enrolment is shown and blocks that edge's director data, never
    resolved automatically; an edge leaving the clerk's roster is bad news, not a decommission.
26. **Everything is on record:** every GUI action, signed or not, goes into the evidence log (decision 0025) with the
    broker subject, the session and the source address; unsigned actions are listed to all officers daily.
27. **The pin in the code** is the fleet's long-term key or CA, not its leaf certificate, and rotates by an officer's
    statement. During an outage of the fleet or the GUI, edges keep their release and minimum, and enrolment waits.

Open for the operator (decide loop): the director's form and downgrades (C2), who may read the fingerprint (H4), child
fleets' registries (H6), registry thresholds, delay and recovery (H7), the install anchor and re-anchoring (H8), and one
officer versus two for relays and child fleets (M1). Decided in round 2 below.

### Round 2 (operator, decide loop on the red team's open findings, 2026-10-25)
28. **The director** (C2): its choices are signed by a director key the offline release root names and can revoke,
    and expire (a stopped or frozen director runs out). An edge's floor is the highest of the offline-signed group
    floor, the clerk's minimum and its installed release; it refuses anything below, alarms and keeps its release. The
    director may return an edge to the previous offline-signed release it ran; anything further back needs an offline
    downgrade statement. Residual: a compromised director can pin edges one release back (alarmed; the floor holds).
29. **Registry rules** (H7): each registry is versioned and names the previous one by hash, and checkers pin the
    highest version seen; removing an officer takes a majority, and the registry never has fewer than three officers;
    of every two signatures one is device-bound (not a synced passkey); a change takes effect after 48 hours, every
    officer notified and any one able to veto; a co-owner's hardware key is a standing officer for recovery.
    Break-glass: a majority including at least one device-bound key may waive the delay; the waiver alarms every
    officer at once, goes into the evidence log and is reviewed after.
30. **The anchor** (H8): the first officers prove possession by signing registry version 1 at their first sign-in, so
    an installer alone cannot complete it; the anchor's hash travels in every enrolment code and is recorded with the
    parent and the clerk; a re-anchored fleet is a new identity, which edges and the parent alarm on and re-enrol to.
31. **Site fleets** (H6): a site fleet keeps its own anchor; the parent shows its edges as "vouched by site X", never
    as its own enrolments, and accepts a report through the site only if the edge signed it and is in that subtree.
32. **Approvers** (M1): one officer's passkey for every enrolment, relays and site fleets included (the GUI red team's
    two-officer constraint is withdrawn). Residual, stated: admitting a relay or site fleet is one person's decision;
    its edges stay labelled as vouched by it.
33. **Reading the fingerprint** (H4): whoever is at the edge may read it to the approver by any channel; the approver
    records who read it and how. Residual, stated: a phisher posing as the installer (the Storm-2372 shape) is met only
    by that record, the 80-bit check, the proof of possession and the "slot already taken" alarm. Exception (operator,
    on acceptance): admitting a relay or a site fleet requires the approver to read the fingerprint from its screen
    themselves, since there one person (point 32) decides what the parent believes about a whole subtree.
Points 14-33 accepted by the operator, 2026-10-25, with that exception.

## Consider the opposite
Let the clerk hold the fleet view (KeyClerk's first proposal): one store, no second service. Against it: ReliKey
would then offer no fleet management without KeyClerk, against the rule that any clerk is a stand-in; and device
facts would drift into the governance store.

## Build state (2026-10-29)
- Built: the fleet service `relikey-fleet` (its own Go module `fleet/`: signed edge reports, the inventory and the
  silence alarm, point 1's self-reported label), the fleet page (point 13), the anchor ceremony (points 16, 21, 30), and
  the officer registry and enrolment building blocks (points 14 to 33). Described in `docs/fleet.md`.
- Not built: signed releases and the enforced minimum release (slice 3), staged rollout (slice 4) and the site relay
  (slice 6), tracked in #33; enrolment-key rotation (slice 5), tracked in #26; a clerk's governance facts.

## Changelog
- 2026-10-29: the build state recorded (#86); the decision unchanged.
- 2026-10-28: note on point 20: for 0.2.0 the fleet alone checks an activation (display and report intake only,
  re-verifiable from the evidence log); the clerk as a second checker follows (#23).
- 2026-10-25: points 14-33 accepted (operator), with one tightening: a relay or site fleet is admitted only with the
  approver reading its fingerprint themselves.
- 2026-10-25: round 2 (points 28-33): the director signed, expiring, one release back free; registry rules with
  a 48 h delay and break-glass; the anchor proved and recorded; site fleets anchor themselves, labelled; one
  officer everywhere; anyone may read the fingerprint, recorded. Awaiting acceptance.
- 2026-10-25: amended (points 14-19) after the decide loop on fleet administration and enrolment: no authority on the
  fleet server, enrolment by code and passkey, the officer registry anchored at install, a clerk only through a neutral
  contract (the director moves to the fleet), no DNS discovery, rollouts paced in the GUI.
- 2026-10-25: red team of points 14-19 (two critical, eight high): tightenings taken in as points 20-27; six
  findings open for the operator; points 14-19 proposed, not accepted.
- 2026-10-25: point 13, the fleet page behind the broker (design; the OIDC client's form open for review).
- 2026-10-25: point 13 after its red team: in process, own module, a client role, own loopback port.
- 2026-10-25: amended (points 7-12) after verified prior art: Uptane's model on go-tuf, rollback outside the agent,
  the read-only invariant, rollout guards, a skew of two releases, an outside watch.
- 2026-10-25: accepted (operator).
- 2026-10-25: KeyClerk 0027 (2fa2e25, 4205d60) takes in the red team in full; the withholding residual stated.
- 2026-10-25: draft 2 after the red team: an enforced minimum release that also bounds rollbacks and holds; ordered,
  non-replayable tightenings; relay-ordered ends as suspensions; no relay delegation; one replacement per edge with a
  silence period and a freeze when the original returns; TUF-style release keys and an outside health gate; the
  self-reported label without a clerk; backfill trust stated.
- 2026-10-25: proposed (decide loops on fleet management and its federation; KeyClerk's view).

# 0017: The edge-decision interface is the security profile of the edge protocol; KeyClerk is its reference emitter

- Status: accepted (operator, 2026-10-25), draft 2 after the review of 2026-10-25
  (a review record kept with the maintainer, E-1..E-9), on the condition the operator set in the decide loop: a
  test emitter without KeyClerk's code passing the agent's verifier (`agent/internal/testemit`, met 2026-10-25)
- Date: 2026-10-24 (draft 1), 2026-10-25 (draft 2)
- Extends: 0016. Narrowed by 0023 point 3 (the clerk role is the published edge protocol).

## Context

The red team of the agnosticism model (a review record kept with the maintainer, F2) found the real
coupling: the edge agent is frozen to KeyClerk's edge wire (the conformance vectors, `kc-edge-bundle-v3`, the sealed
object shape, modules by sha256, the Go port of `ceiling.rego`). So "clerk is swappable" was circular: a substitute
IGA would have to emit KeyClerk's exact bytes. Draft 1 answered with a second, neutral contract beside the wire.
Since then 0023 (accepted) made the clerk role "whatever speaks the published edge protocol", and the midPoint adapter
measured the gap: a general IGA supplies 1 of 6 properties. A second contract beside the protocol would now define
the clerk seam twice (review E-1).

## Decision

1. **One seam, two layers.** The clerk seam is the published edge protocol (0023 point 3). The edge-decision
   interface (EDI, `model/edge-decision-interface.yaml`) is that protocol's **security profile**: the properties the
   agent verifies, stated without product names, so a reviewer can check any emitter against them and an implementer
   knows what fails closed. It is not a second wire format: an emitter speaks the protocol; the EDI says which of the
   protocol's guarantees are load-bearing.

2. **Scope, stated.** The EDI profiles what the agent consumes for access: the bundle (decisions, visit leases,
   revocation, serial, horizons, governed roles) and the officer's sealed ceiling (C-04, C-06, C-10). The rest of what
   the agent consumes is reference-only, bound to KeyClerk's formats until each has its own profile: the enrolment
   statement and cosign, ended notices, carried leases (C-07), unlock (C-08), escrow (C-09), evidence (C-12), the
   relay (C-03), modules by hash, and signed edge requests (review E-2).

3. **Two keys, never one.** The ceiling is signed by the edge officer's key, which the emitter does not hold, and the
   agent checks it at every bundle against its own pin. An emitter that signs bundle and ceiling with one key does not
   conform, whatever else it does: it collapses the two-key model of 0007 (review E-3).

4. **The verifications are the reference's, complete.** The agent refuses: a signature that does not verify against
   the pinned key over the exact signed bytes, with the format tag inside them; a bundle for another edge; a serial
   not above the stored floor (a re-fetch of the bundle already held is not applied again); an issue time beyond the
   skew in the future, or before the newest signed time seen; a clock before that newest time; a ceiling below the
   stored ceiling serial or not sealed by the pinned officer; a decision outside the ceiling or its class horizon; a
   malformed governed-roles member. Algorithms follow 0022
   (Ed25519 now, a hybrid signature format later, chosen by format tag, never guessed) (review E-4, E-5).

5. **Subjects are the broker's.** A decision's subject is the broker's stable identifier for the person (the realm's
   anchor), plus the holder key for a visit lease; never a display name or an e-mail, so the subject space and the
   bastion's account names cannot be confused (review E-6).

6. **KeyClerk is the reference emitter; a second emitter is a test.** `kc-edge-bundle-v3` and `kc-edge-ceiling-v2`
   are the reference binding, verified by the agent against KeyClerk's conformance vectors. A test-only second
   emitter, written without KeyClerk's code, must produce bundles the Go agent's verifier accepts, and the vectors'
   refusals must refuse, as 0023's in-memory bastion does for the bastion role (review E-9). No second emitter ships.
   Built 2026-10-25: `agent/internal/testemit` emits bundles and sealed ceilings from the published format with its
   own encoding and signing (a test refuses any import of the verifier or KeyClerk's code); the agent's verifier
   accepts them, and refuses each of eleven breaches of point 4 for its own stated reason (a wrong key, one key for
   both, re-serialised bytes, another edge, replay, a future or stale issue time, a clock set back, an old ceiling, a
   malformed catalogue, leases without a ceiling); decisions outside the ceiling or past their horizon are not live.

7. **A clerk adapter adds the residue, and we say how much.** A general IGA supplies the raw grants (subject, target,
   validity). Everything else is residue the adapter must add. Measured (2026-10-24): midPoint supplies 1 of 6; the
   clerk role is KeyClerk-shaped in substance, and ReliKey claims no clerk agnosticism, only a published protocol any
   clerk may implement (review E-8).

## Consequences

- The honest claim is precise: one published protocol, one security profile, one reference emitter, one test
  emitter. Clerk agnosticism is not claimed.
- NIST SP 800-207, stated: the clerk is the policy engine and administrator; the agent and the bastion are the
  enforcement point. Two deviations, deliberate: decisions are computed in advance with offline horizons rather than
  per session (tenet 3; the edge must work without a network, 0006), and the agent evaluates the ceiling locally as a
  decision point that can only narrow. "The agent decides nothing" means it grants nothing the clerk did not.
- Revocation is by omission in a newer bundle: it takes effect within one pull interval of the clerk's change (60 s by
  default) while the edge is connected, and at the class horizon when it is not.
- Prior art, stated: OpenID AuthZEN Authorization API 1.0 is an online evaluation call and does not fit decisions
  computed in advance for offline use; the EDI borrows its vocabulary (subject, action, resource, context). TUF
  (version floors, expiry, freeze defence, pinned keys) and OPA signed bundles (signature and revision) are the closer
  references for the property list; the EDI adds the rollback floor OPA lacks.
- Work item: the midPoint adapter run against the Go agent's verifier rather than its own (review E-7; until then the
  behavioural conformance review says "its own verifier"). The second emitter (point 6) is built.

## Consider the opposite

Drop the EDI and point at the protocol alone: one document less. Against it: the protocol says how; only a profile
says which guarantees an emitter may not weaken, and the one-key emitter in draft 1's own adapter shows that this is
the mistake an implementer makes.

## Changelog
- 2026-10-25: accepted (operator).
- 2026-10-25: the test emitter built and passing (point 6); the ended notice moved out of point 4 (it is
  reference-only, point 2).
- 2026-10-25: draft 2 after the review (E-1..E-9): the EDI becomes the edge protocol's security profile (0023), scope
  stated, two keys required, the reference's full verification list, broker subjects, a test-only second emitter,
  the measured outcome and the 800-207 deviations recorded.
- 2026-10-24: proposed.

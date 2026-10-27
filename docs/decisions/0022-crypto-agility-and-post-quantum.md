# 0022: Crypto agility and post-quantum migration: lead time first, inventory proved, formats by KeyClerk

- Status: accepted (operator, 2026-10-24), draft 2 after the red team. Part A is being built in ReliKey; part B is
  KeyClerk's (its decision of 2026-10-24, below), after its engine is public, except the rotation anchor's key.
- Date: 2026-10-24
- Builds on: 0005, 0007, 0009, 0011, 0013, 0021 (the CBOM), KeyClerk's edge interface (versioned formats, KC-4)
- Red team: five angles (format and protocol design, keys and hardware, components and compatibility, threat model,
  governance and cost) and a prior-art scan; the record is kept with the maintainer.

## Context
Draft 1 prioritised confidentiality by a regulatory date: hybrid encryption first where secrets outlive 2031, signatures
later. The red team inverted that.
- **Lead time is the real risk.** What cannot be fixed later is the forgery of long-trusted anchors:
  - pinned roots on sites that are hard to visit;
  - unlock keys;
  - evidence chain heads that audits rely on years later.
- **Two angles found the same flaw independently.** A "floor that only rises" carried in an Ed25519-signed ceiling, and
  a key rotation signed by the key it replaces, protect nothing against the adversary they are meant to stop, and a
  forged high floor can brick an edge.
- **Draft 1's gap list was wrong both ways.**
  - It named two gaps that do not exist: Keycloak never terminates network TLS (Caddy does), and Warpgate already prefers
    hybrid key exchange on SSH and HTTPS.
  - It missed the real ones: Keycloak's JDK as a TLS client to the organisation's IdP, Keycloak's token signing keys, the
    CA the agent pins, clients outside ReliKey's control, and legacy targets that fall back to plaintext.

What is mature (prior art, 2026):
- **Hybrid key exchange for TLS:** RFC 10024 (X25519MLKEM768). It is the default in Go, rustls (aws-lc-rs) and OpenSSL
  3.5, and OpenSSH warns when a connection does not use a post-quantum key exchange.
- **Hybrid signatures:** prior art exists (OpenSSH ssh-mldsa44-ed25519; the IETF LAMPS composite ML-DSA draft).
- **Pinned-key rotation:** the TUF chain (version N signs N+1, with thresholds and expiry).

What is not mature:
- ML-DSA on hardware tokens: none found. ML-DSA in hardware means an HSM or a cloud KMS.
- Post-quantum passkeys in Keycloak and in hardware authenticators. They do exist in software (RFC 9964).

## Decision

### A. ReliKey decides now
1. **Agility is versioned formats, never negotiation.** One suite per format version, compiled in; no algorithm chosen
   by configuration. For signed formats this defers to KeyClerk (part B).
2. **The crypto inventory is generated and proved, not written.** It is derived from model/flows.yaml and the pinned
   versions: image digests, Cargo.lock for Warpgate, go.mod and the Caddy build. For each link it records both ends,
   the key exchange, the signatures, the trust anchors and a conditional quantum status (for example, "hybrid if the
   client supports it"). It includes:
   - Keycloak's realm keys, the CA the agent pins, the password manager that holds the escrow, and the formats.
   - Each crypto claim cites a component-facts entry saying how it was checked, invalidated when a digest changes.
   - The full-stack run probes every TLS and SSH link for the group it actually negotiates.
   It is ReliKey's part of 0021's CBOM.
3. **Transport policy per link.** Where both ends are ReliKey's (the agent to the desk, the edge to the core, the front
   to the core's services), hybrid key exchange is required. Each link states whether a non-hybrid fallback fails closed
   or is allowed visibly, and the agent reports the negotiated group in its status. Links whose other end is a person's
   client or a legacy target record what was negotiated and keep a per-target floor:
   - no SHA-1 Diffie-Hellman;
   - no plaintext fallback, which Warpgate's "preferred" TLS mode allows today.
4. **Evidence keeps its integrity for audits years later.** The heads of ReliKey's hash-chained evidence are anchored
   regularly with a hash-based signature (SLH-DSA, or LMS/XMSS per SP 800-208) or an RFC 3161 timestamp, and renewed
   under an RFC 4998 evidence record policy. This runs in the core, needs no tokens, and is cheap.
5. **What ReliKey may claim**, until part B lands: "an inventory of the cryptography on every link and signed format,
   with its quantum status; hybrid post-quantum key exchange on the links ReliKey controls; signatures, officer keys and
   passkeys still classical, with a documented plan". Primary sources only. Nothing else is called post-quantum.
6. **Residuals, stated:**
   - Keycloak's JDK as a TLS client (F-12) and its token signing keys;
   - Windows' bundled OpenSSH 9.5 (sntrup761 only, which russh lacks) stays classical;
   - TLS inspection re-originates connections classically;
   - the legacy hop;
   - passkeys: post-quantum ones exist in software, but not in Keycloak or hardware authenticators.
   Each has an upstream item with its trigger.
7. **FIPS is decided before a hybrid suite is chosen for a format** (part B), because Go FIPS, rustls FIPS and the
   JDK's BCFIPS may differ on X25519 hybrids. A FIPS profile itself is deferred until a customer asks.

### B. Requirements for KeyClerk's decision, in order of lead time
1. **A post-quantum rotation anchor at enrolment.**
   - Every edge enrolled from the day it exists pins an offline, stateless hash-based key (SLH-DSA), used only to
     authorise rotations of the other pins and raises of the floor.
   - Rotations form a chain co-signed by the anchor and the officer, as in TUF, with thresholds, expiry and a revocation
     list.
   - An edge with no valid path fails closed and is re-pinned on site.
   - The lead time is set by reach, not by 2035: an edge reachable before a quantum computer exists can gain the
     anchor through an Ed25519-signed rotation done before then; only an edge that stays unreachable until then needs a
     site visit. Pinning it at enrolment avoids depending on that rotation.
2. **A floor that the adversary cannot set and that cannot brick.**
   - The object that carries the floor is signed at or above the floor it sets: by the anchor until the officer's
     signatures are hybrid.
   - The minimum suite is also pinned on site at enrolment and kept where the profile protects floors.
   - A floor never exceeds what every node of the edge has proven it supports. An unknown value is refused while the
     held ceiling stays.
   - Recovery from a wrong high-water mark is an on-site officer act.
   - A dated sunset compiled into the agent is the backstop.
3. **Unlock redesigned as a forgery risk.** A symmetric unlock secret is established once at enrolment by hybrid key
   encapsulation and sealed in the TPM where there is one. The phoned code stays an HMAC of the same length, and unlock
   keys rotate.
4. **Escrow replaced, not re-wrapped.** New escrow under a standard hybrid KEM combiner (HPKE with ML-KEM, or X-Wing
   once stable), its KDF context binding format, purpose, ciphertexts and recipient keys. Existing escrow is retired by
   rotating the credential, never by reassembling and re-wrapping it.
5. **A composite signature format** following the LAMPS composite and OpenSSH rules:
   - fresh component keys, never used alone;
   - label-bound and pre-hashed;
   - neither part verifies in isolation;
   - key_id over both keys, a fixed order.
   Custody rule: the post-quantum half is never in weaker custody than the classical half; until hardware allows,
   software-held keys sign only what the officer's policy limits. Conformance vectors cover stripping, swapping,
   relabelling, floors and combiner known answers.
6. **The lease relay last.** Lease credentials rotate at lease end, so harvest-now risk is low. Static device passwords
   are rotated instead, the cheaper control.

### KeyClerk's decision so far (operator, 2026-10-24)
- Hybrid encryption decided now: break-glass values rotate monthly from now; then HPKE (RFC 9180) with a hybrid KEM
  (X25519 plus ML-KEM-768), escrow first and lease envelopes after; suite ids inside the format, the allowed set fixed
  per version under a signed floor, never negotiated (B4, B6).
- A hybrid Ed25519 plus ML-DSA signature format decided by the end of 2028 and shipped by 2030 (B5).
- A CycloneDX CBOM of KeyClerk's cryptography with every release, held to the code by a test (A2's KeyClerk side).
- An offline SLH-DSA rotation anchor pinned at every edge's enrolment from the next enrolment format, co-signing key
  rotations and floor raises with the officer (threshold, expiry, revocation); no valid chain fails closed and is
  re-pinned on site; the floor travels in an object signed at or above it, never above what every node proved it
  supports; recovery is an on-site officer act (B1, B2).
- Phoned unlock in scope: a new unlock format with a symmetric secret agreed at enrolment by a hybrid KEM, TPM-sealed
  where present; codes keep their length; unlock keys rotate (B3).
- Monthly break-glass rotation is part of building the escrow (C-09), not something that starts before it exists.
- KeyClerk writes one decision record for all of it, with this red team as input and a red team of its own.
- Placement: the crypto-agility work comes after KeyClerk's engine is public; one exception: the rotation anchor's
  public key is pinned by the 0.29.0 enrolment format. In 0.29.0 the edge only stores it (with the other pins, never
  taken from the desk, shown on the status page); the co-signed chain comes later.

## Consequences
- ReliKey's part is inventory, probes, a transport policy, evidence anchoring and honest claims: work that fits one
  person and a grant milestone (NLnet NGI Zero).
- KeyClerk's part sets the pace for the long-trusted anchors. The enrolment deadline makes the rotation anchor the first
  thing worth building.
- Budget: one hybrid format per release, when a grant or a customer pays for it.

## Rejected (draft 1)
Ordering by "secrets outliving 2031"; a floor carried in an Ed25519-signed ceiling; rotation signed by the key it
replaces; re-wrapping escrow; a hand-written gap list; "post-quantum" claims beyond the inventory.

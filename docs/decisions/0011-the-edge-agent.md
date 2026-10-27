# 0011: The edge agent - Go, one static binary, signed decisions only; slice 1

- Status: accepted (operator, 2026-10-23: R-08 "Go"; first slice "online path end to end")
- Date: 2026-10-23
- Closes R-08. Builds on 0005 (the edge), 0007 (signed policy run as WebAssembly, no OPA daemon), 0010 (Keycloak and
  Warpgate) and the KeyClerk edge interface (KeyClerk 0014 to 0014c, v0.19.0; `docs/keyclerk-edge-interface.md`).

## Decision
1. **Go, one static binary** (`CGO_ENABLED=0`) for linux amd64, arm64 and armv7 (hard float). Switches on MIPS or
   PowerPC SoCs are not supported until the policy runtime is tested there.
   Cryptography from the standard library (Ed25519, X25519, P-256 ECDH for the phoned unlock since KeyClerk 0.23.0, HKDF, AES-GCM, SHA-256); the signed Rego policy modules
   run in process with wazero (pure Go). No other runtime on the edge. Expected additions with their reasons:
   `github.com/google/go-tpm` (assured profile), `golang.org/x/crypto/ssh` (carried-lease proof of possession).
   How to write and build it: `docs/go-engineering.md` (red-teamed, GE-1 to GE-20).
2. **It decides nothing of its own.** It verifies what KeyClerk signed - exactly as `keyclerk.edge.verify_bundle` and
   `verify_carried` do, proven by KeyClerk's conformance vectors (`tests/conformance/edge.json`) run in the agent's own
   tests - evaluates the signed `edge` and `ceiling` modules, and applies the result.
3. **It applies through documented APIs only**: Warpgate's admin API on loopback (users, SSO credentials, role
   assignments with `expires_at`, session approvals, terminating sessions), the facade's admin API on loopback, and
   KeyClerk's signed edge routes outbound.
4. **State on the edge is small and explicit**: the pinned keys, the floors (bundle serial, newest signed time,
   ceiling serial, per-person carried serials), the applied serial, the chained evidence log. On assured edges the
   floors live in the secure element (0007, 0008).
5. **Layout** in this repository: `agent/` (Go module `relikey/agent`): `cmd/relikey-agent`, `internal/kcedge`
   (formats, signatures, verifier), `internal/policy` (wazero), `internal/warpgate` (admin API client),
   `internal/apply` (bundle to Warpgate state, drift), `internal/state`.

## Slice 1 - online path end to end
In scope: enrolment keys and pinning; signed requests; pull, verify and apply a bundle; Warpgate user, SSO credential
(0010) and role assignment with expiry per lease; removal when a lease ends; drift report; the 0010 Warpgate and
Keycloak configuration; a podman composition of Keycloak, KeyClerk, Warpgate and the agent; one e2e test on a lab box:
a lease granted in KeyClerk, sign-in through Keycloak, a recorded SSH session through Warpgate, the lease ended, the
session ended.

Not in slice 1: the LDAP facade and lease credentials (P-B, P-D), the filtering proxy (until #2782), offline levels
(visit, carried, unlock, break-glass), evidence backfill, hardware profiles and attestation, remote reach.

## Changelog
- 2026-10-23: accepted; after the Go red team: targets narrowed to three (no MIPS/PowerPC), expected dependencies
  named, engineering rules linked; the TPM curve question is R-19.
- 2026-10-23: slice 1 core built (`docs/agent.md`): verifier, ceiling policy (Go port of ceiling.rego until wazero),
  state, trusted time, reconcile, shadow mode (canary), soak harness; red-teamed (AG-1 to AG-22).

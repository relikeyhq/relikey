# The KeyClerk edge interface

**Source of truth:** `docs/keyclerk-edge-interface.md` in the KeyClerk repository (github.com/keyclerk/keyclerk), tag
`v0.23.0` (commit bd6620f), with KeyClerk decision 0014 and amendments 0014a to 0014d. v0.21.2 and v0.22.0 fixed the
Go port's findings KC-1 to KC-3 and KC-5 to KC-11 (`a review record kept with the maintainer`); v0.23.0
adopts KC-4 (amendment 0014d, one signing mode over exact bytes), R-19 (kc-unlock-v2 over P-256) and AG-18 (the ended
notice bound to the enrolment keys it ends), and names policy modules by hash. The reference implementation is
`keyclerk/edge.py`; `tests/conformance/edge.json` holds 107 cases with fixed keys (policy, bundle verifier, and the
families statements, ceilings, ended, unlock, module_bytes); tooling is `python -m keyclerk.edge_cli`. ReliKey's agent
conforms to that document and those vectors (all 107 pass, plus ReliKey's own tests for two guards the set does not
exercise yet); this page only maps it to ReliKey.

## What changed for the agent in v0.23.0
| KeyClerk 0.23.0 | The agent |
|---|---|
| A sealed object is exactly `{bytes, signature, key, key_id}`; base64 canonical; the re-encoding check guards the parse, never the signature | `kcedge.SealedFrom`/`UnsealValue` refuse extra members; the desk client decodes with `RejectUnknownMembers`; base64 is compared after re-encoding (Go skips line breaks even in strict mode) |
| `kc-edge-bundle-v3`: the ceiling is the officer's sealed `kc-edge-ceiling-v2`, carried exactly as sealed | `kcedge.CheckCeiling(edge, officer, sealed, floor)` unseals with the officer key; nothing is re-serialised |
| `policy.modules = {name: {sha256}}`; bytes from `GET /api/v1/edge/module/{sha256}`, checked with `verify_module` | `ModuleRefs`, `VerifyModule`, `keyclerk.FetchModule`; kept by hash in the state directory, fetched once per policy change; a failed fetch is counted and retried, never blocks the bundle (the ceiling decision runs in the Go port of ceiling.rego until the module runtime lands) |
| `kc-edge-officer-v2` multi-signed `{bytes, signatures}` with purpose and nodes `{enrolment_key, unlock_key, tpm}` | `kcedge.UnsealMulti`, `Cosign`; CLI `relikey-agent statement` (show) and `cosign` (checks the statement names this node's enrolment and unlock keys); interop proven: KeyClerk's `unseal_multi` accepts a statement cosigned by the Go agent |
| `kc-edge-ended-v2` `{edge, ended, reason, enrolment_keys}` | `VerifyEnded(sealed, pins, own enrolment key)`; a notice for other keys is refused and access stays (agent test) |
| kc-unlock-v2: P-256 ECDH, HKDF info binding edge, node and both keys, 10-character base32 code | `kcedge.UnlockSecret`/`UnlockCode`; CLI `unlock-keygen` (software key, no TPM) and `unlock-code` |
| A desk in restore mode answers 503 (0.25.0) | already an outage: leases run on their horizons, never an ended edge |

## What it gives ReliKey (v0.18.0)
| ReliKey | KeyClerk edge interface |
|---|---|
| C-04 signed bundles, C-10 ceiling (0007, R-18) | Signed objects are exact bytes `{bytes, signature, key, key_id}`, no floats, each naming its format (`kc-edge-bundle-v2`, ...). The bundle carries the officer-signed ceiling. The agent pins three keys on site: the bundle key (key id read out by the desk operator), the officer key, optionally a policy release key; it keeps floors for serial, newest signed time and ceiling serial; leases are capped at min(class horizon, `ceiling.max_offline_hours`); another edge's bundle and a future issue time are refused; lease ids are stable; `GET /edge/bundle?serial=N` re-fetches. |
| Edge requests | `kc-edge-request-v2`: edge id, method, path, seconds, nonce, sha256(body), Ed25519 by the enrolment key. |
| Enrolment, officer independence (0007) | The officer and the edge each sign `kc-edge-officer-v1` `{edge, enrolment_key, officer, officer_key}`; independence from the core is re-checked at every ceiling and bundle, failing it freezes the edge. |
| Who a lease may admit | A role (core group) in the ceiling admits only low-class leases; elevated, privileged and visit leases need the person named in the ceiling. |
| C-01, C-06 lease application, 0010 | Leases carry `username` (the broker username), the holder's person `key_id` and `public_key`, and `max_session_hours` (edge.rego: low 8, elevated 4, privileged 1, or the target's cap). Visit leases carry the role. |
| C-03 lease credential to the person (0009 M2) | Relay accepts only purpose `lease:<id>`, to a holder of that lease, envelope context equal to the purpose (`kc-relay-v1`: X25519, HKDF-SHA256, AES-256-GCM). |
| C-09 break-glass escrow (0008 H3) | Custodians designated at enrolment; halves kept until each custodian confirms; poll `GET /edge/escrow/{item}`, forget the value only when confirmed. |
| C-12 evidence (0009 M1) | Evidence resend is a no-op; `GET /edge/evidence` returns the head. |

## Slice D (v0.19.0, 0014c; KeyClerk interface sections 9 to 11)
| ReliKey | KeyClerk |
|---|---|
| C-07 carried visit lease (0006 level 3) | `kc-edge-carried-v1` issued to the person after a fresh sign-in, at most `carried_max_hours` (24, edge.rego) inside the visit lease; the agent checks it with `keyclerk.edge.verify_carried` (own edge, window, per-person serial floor) **plus proof of possession of the SSH key, which is ReliKey's to build** |
| C-08 phoned unlock (0006 level 4, 0008 H4) | since v0.23.0 kc-unlock-v2: each node has a P-256 unlock key (in its TPM where it has one), named in the statement; secret HKDF-SHA256 over the ECDH x coordinate with info `kc-unlock-v2|edge|node|desk_key|node_key`; the code is base32 of an HMAC over edge, node, person, key fingerprint, target, nonce and minutes, cut to 10 characters; approver never the person; `unlock_max_minutes` 60, `unlock_per_hour` 3; every unlock is logged and raises a `phoned_unlock` incident. (Superseded: kc-unlock-v1 over X25519, never deployed.) |
| Lifecycle | `rotate_edge` (new enrolment key or officer, both sign, the security officer completes); an ended edge gets 410 with a sealed `kc-edge-ended-v2` naming the enrolment keys it ends (AG-18; v1 superseded); `edge_silent` after `pull_max_hours` (24); incidents capped at 60 an hour; `evidence_fork` once per head; an SSH key belongs to one person |

Fix to note: ending an edge, a person key or a visit lease was refused in 0.17.0 and 0.18.0; anything ReliKey tests
about ending records must use 0.19.0 or later.

## Changelog
- 2026-10-24: pinned to v0.23.0 (107 cases); the agent ported (one signing mode, modules by hash, kc-unlock-v2,
  bound ended notice). The "What it gives ReliKey (v0.18.0)" table below keeps its history; where it names v1/v2
  formats, the section above supersedes it.
- 2026-10-23: pinned to v0.22.0 (56 verifier cases, including ReliKey's 34 contributed ones).
- 2026-10-23: pinned to v0.21.2; the agent's vectors regenerate from it (`agent/internal/kcedge/testdata/regen.py`).
- 2026-10-23: v0.19.0 slice D mapped (C-07, C-08, lifecycle).
- 2026-10-23: v0.17.0 interface first recorded here; replaced by a pointer to KeyClerk's own document for v0.18.0 (wire
  format v2 after KeyClerk's red team and gap review).

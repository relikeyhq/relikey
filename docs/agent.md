# The edge agent (relikey-agent)

The agent is the only ReliKey code on an edge (decision 0011). It verifies what KeyClerk signed and makes Warpgate
hold exactly what the live leases allow; it decides nothing of its own. Code: `agent/` (Go 1.27.3, one static binary
for linux amd64, arm64, armv7). How it is written and built: `docs/go-engineering.md`.

## What it does, every 15 seconds and every minute
- **Every pull** (60 s, jittered): `GET /api/v1/edge/bundle`, signed with the enrolment key (`kc-edge-request-v2`).
  The bundle is verified exactly as `keyclerk.edge.verify_bundle` does, plus the officer's ceiling policy, against the
  floors (serial, newest signed time, ceiling serial). Floors and the bundle are stored **before** anything is
  applied; a refused bundle changes nothing. A 410 with a valid sealed ended notice ends the edge for good.
- **Every tick** (15 s): the live leases are recomputed from the stored bundle at the **trusted time**, so leases end on
  the edge without asking anyone; Warpgate is read, a plan is computed, and (in enforce mode) executed. A read that
  fails transiently (a transport error, a 5xx or a 429) is asked again within the tick, at most three reads with a
  short doubling wait that never runs past the tick or a shutdown; a rejected token or a cancelled read is not asked
  again. If no read succeeds, nothing is changed that tick and `observe_errors` counts it (fail closed).
- **Trusted time**: the wall clock, unless the boot clock (CLOCK_BOOTTIME, counts suspend) since the last verified
  bundle says more time has passed; then the later time wins and the skew is reported. A wall clock set back cannot
  keep a lease alive. After a reboot (boot id changed) nothing is live until a fresh bundle verifies.
- **The plan**: close sessions that no live lease reaches (or that ran past `max_session_hours`, or whose user no longer
  exists), then remove roles, SSO credentials and every other credential, delete users without leases, then create
  users (stripping Warpgate's default roles), add SSO credentials (provider and e-mail, decision 0010) and roles
  with `expires_at`.
  Since edge protocol 1.3 the bundle carries no address: the agent fetches each live lease's verified address from the
  desk, sealed for that request, and keeps it in memory only. A failed fetch is retried after 15 s; an answer without
  an address is asked again no sooner than a minute later, because the desk can learn the address after the lease went
  live (full-stack run 8: until then the person's SSO sign-in finds no user). Every step is idempotent; a failed step is retried by the next tick's plan. Only users whose description is the
  ReliKey marker are ever touched; two people under one username get nothing.
- **Reports**: after each pull, `POST /api/v1/edge/report` with the applied serial, the drift and the agent version.
- **Writes to disk**: edge hardware often boots from flash, so an idle tick writes nothing. The state slots are
  written only when the record changes. The status files (`status.json`, `status.html`, `metrics.prom`) are written
  when their content changes (the time, the tick and pull counts and the runtime gauges aside), and otherwise at a
  **heartbeat of 60 s**: `updated` in status.json and `relikey_agent_status_updated_seconds` are never older than
  that on a live agent, well inside the canary gate's default `-max-age 2m`, so a reader still tells a live agent
  from a stalled one. A pulled bundle with a new serial is stored even when its content equals the bundle held:
  its serial and signed time are the replay floors, and without them an older bundle issued in between (one with a
  lease revoked since) would verify again; it also re-anchors the trusted time.

## The bastion's settings
Each tick the agent reads the bastion settings ReliKey depends on and, in enforce mode, restores them (shadow mode
only reports): no self-service credentials (a person could add a password, key or token the broker never sees, or
make their account unreadable to the agent), no password SSH, API tokens of at most an hour. A bastion adapter
offers this through the optional `bastion.Hardener`; without it the settings are unchecked. An account the agent
cannot read is still closed and deleted once no lease is live; with a live lease nothing is changed blind.

The settings stop new credentials; the plan removes the ones already there. A managed account signs in only through
the lease's SSO credential or a visit lease's key, so every other credential on it (on Warpgate: passwords,
one-time-password seeds, client certificates) is removed on the next tick in enforce mode, however it got there:
made before the agent ran or before the settings were restored, by an administrator, or by an import. The same
holds for a key no live visit lease installs and an SSO credential that is not the lease's. Unmanaged accounts keep
theirs. A credential list that cannot be read makes the account unreadable for that tick, never "holds none". API
tokens are not listed by Warpgate's admin API; the one-hour cap bounds them.

## A role reaches only its leases' targets
A bastion role grants every target bound to it, and the ceiling checks only the lease's target. So the agent assigns
a role only if every target it reaches is named by the live leases (or visit leases) granting it; otherwise the
drift report names the extra targets and the role is not assigned. A lease without a target is refused. Roles whose
targets cannot be read are not assigned that tick (fail closed, AG-11): bind each role to the targets its leases
name.

## Packages
| Package | Role |
|---|---|
| `internal/kcedge` | KeyClerk's edge interface in Go: canonical JSON, sealed objects, bundle verification, the ceiling policy, signed requests, the ended notice |
| `internal/state` | A/B slots with generation and sha256, atomic writes through `os.Root`, floors only rise, exclusive lock, status.json |
| `internal/clock` | wall and boot clock behind one interface; `Trusted` |
| `internal/httpx` | per-peer HTTP clients: timeouts, no redirects, no proxy, capped bodies, certificate pinning |
| `internal/keyclerk` | signed pull and report |
| `internal/warpgate` | the admin API on loopback; idempotent requests retried with backoff |
| `internal/apply` | desired state from leases, observed state of Warpgate, the ordered plan, execution with shutdown grace |
| `internal/agent` | the loop, shadow mode, status |
| `internal/fakes` | KeyClerk and Warpgate stand-ins for tests and the soak (never shipped) |
| `cmd/relikey-agent` | the binary; `cmd/relikey-soak` the soak harness |

## Running it
As a pod: `deploy/README.md`. As a binary:
```
relikey-agent keygen -out /var/lib/relikey/enrolment.key     # prints the enrolment key to enrol at the desk
relikey-agent unlock-keygen -out /var/lib/relikey/unlock.key  # P-256 phoned-unlock key (software; a TPM key where there is one)
relikey-agent statement -in st1.json                          # what the officer's statement says and who signed it
relikey-agent cosign -in st1.json -out st2.json -key /var/lib/relikey/enrolment.key -unlock-key /var/lib/relikey/unlock.key
relikey-agent unlock-code -unlock-key ... -key ... -desk-unlock-key B64 -edge E -person P -fingerprint F -target T -nonce N -minutes M
relikey-agent pin -cert /etc/warpgate/tls.certificate.pem     # the Warpgate pin for agent.json
relikey-agent run -config /etc/relikey/agent.json
relikey-agent plan -config /etc/relikey/agent.json            # one shadow reconcile, the plan as JSON
relikey-agent status -file /var/lib/relikey/status.json       # exit 1 when unhealthy
```
`agent.json` (unknown keys are refused):
```json
{"edge": "edge-a", "mode": "enforce", "state_dir": "/var/lib/relikey",
 "enrolment_key_file": "/var/lib/relikey/enrolment.key",
 "pins": {"bundle_key": "<64 hex, read out by the desk operator>", "officer_key": "<64 hex>", "release_key": null},
 "clerk": {"url": "https://keyclerk.example", "ca_file": "/etc/relikey/keyclerk-ca.pem"},
 "bastion": {"kind": "warpgate", "url": "https://127.0.0.1:8899/@warpgate/admin/api", "token_file": "/var/lib/relikey/warpgate.token",
              "pin_sha256": "<from relikey-agent pin>", "sso_provider": "keycloak",
              "governed_roles_file": "/etc/relikey/governed-roles.json"},
 "tick_seconds": 15, "pull_seconds": 60, "long_poll_seconds": 55, "grace_seconds": 5}
```
Refusals at start, each with what fixes it: a state directory others can read or on tmpfs/overlay, a key or token
file others can read, a Warpgate URL that is not loopback, enforce mode without a boot id, a second agent on the same
state directory, state unreadable in both slots. In a container: read-only root, the state directory a volume,
`USER 65532:65532`, all capabilities dropped, `no-new-privileges`; stop timeout above `grace_seconds`.

**Long-poll** (KeyClerk decision 0026, edge protocol 1.2): the agent asks for its bundle with `?after=<serial
held>&wait=<long_poll_seconds>` (signed with the rest of the path, always in that order) on a client of its own with
timeouts above the desk's 55 s hold. The desk answers when this edge's bundle content changes, so a grant or a revoke
arrives in seconds, or when the wait ends, with a fresh bundle that renews the offline horizon. The pulls run beside
the reconcile loop, so ticks never wait behind a hold. A held answer, or one whose content changed, is followed by the
next long-poll at once; an answer with unchanged content that came at once (a desk over its cap, or older than 0026)
by `pull_seconds`, jittered: never a tight loop. `long_poll_seconds`: 0 is 55, at most 55, -1 pulls plainly.

**Events** (decision 0025 point 1): beside its log lines on stdout the agent writes one JSON line per event, told
apart by `"specversion"`: a CloudEvents 1.0 envelope (type `relikey.<noun>.<verb>.v1`, subject an entity id such as
`account:<edge>/<name>`) whose data is an OCSF 1.6.0 event, with a monitoring platform's alert-event fields (`ts`,
`solution`, `event`, `outcome`, `severity`, `reason`, `entity`) as extension attributes. Emitted: each change the agent
made on the bastion (`relikey.account.created`, `deleted`, `role_granted`, `role_revoked`, `role_extended`,
`sso_bound`, `sso_unbound`, `key_added`, `key_removed`, `credential_removed`; `relikey.session.closed`), an
unmanaged account holding a governed role (`relikey.drift.rogue_account`, once when found and once when gone; which
roles stays in the local drift report), a refused bundle (`relikey.bundle.refused`) and an ended edge
(`relikey.edge.ended`). Events name bastion accounts and lease ids, never an e-mail; they are not yet chained or
sequenced (the evidence log, 0025 point 2).

`fleet.url` (optional): the agent sends ReliKey's fleet service its signed report every pull interval
(`docs/fleet.md`, decision 0026); it must be the clerk's own host, and the agent takes nothing back from it.

`governed_roles_file` (optional) is a SCIM list of the groups only leases grant, written by `deploy/edge/targets.py`
from the edge's targets. With it, or with `governed_roles` in the signed bundle (KeyClerk 0.25.0, its decision 0025),
an account the agent does not manage that holds one of those roles is in the drift report and is never changed: the
agent governs the union of both sources (full-stack run 2, finding 8). The file is read every tick; one that cannot be
read or parsed is a note in the drift, never "nothing governed".

## Metrics
Every tick the agent writes `metrics.prom` (Prometheus text) beside `status.json`, for a textfile collector or to be
copied out; it serves nothing. The names below are a stable interface, pinned by a test: a rename or removal, or a
change of type, lands only in a tagged release, listed under Changed or Removed in the changelog. Warpgate exports no
metrics of its own, so `relikey_agent_observe_errors_total` is the only signal of trouble reading the bastion.

| Metric | Type | Meaning |
|---|---|---|
| `relikey_agent_healthy` | gauge | 1 when the canary gate passes (`relikey-agent status`), else 0 |
| `relikey_agent_status_updated_seconds` | gauge | Unix time the status was last written |
| `relikey_agent_live_leases` | gauge | leases live now |
| `relikey_agent_bundle_serial` | gauge | serial of the newest verified bundle |
| `relikey_agent_applied_serial` | gauge | serial whose plan was applied in full |
| `relikey_agent_bundles_refused_total` | counter | bundles and notices refused by the verifier |
| `relikey_agent_action_failures_total` | counter | Warpgate actions that failed |
| `relikey_agent_observe_errors_total` | counter | failures to read Warpgate's state |
| `relikey_agent_ended` | gauge | 1 when the desk ended this edge |
| `relikey_agent_pulls_failed_total` | counter | pulls that failed (desk unreachable or refusing) |

The other metrics in the file (successful pulls, the plan, actions executed, module failures, heap and
goroutines) are diagnostics and may change in any release.

## Canary: shadow mode and the gate
A new agent version goes to one edge first, next to the version that enforces:
1. Run the new version with `"mode": "shadow"`, its own state directory and its own enrolment key (enrolled at the
   desk as a shadow, so its reports do not mix with the enforcing agent's; red team AG-20).
2. It verifies the same bundles and computes its plan against the Warpgate the old version keeps in step. Agreement
   means its plan is empty; `nonempty_streak` in its status.json counts ticks with a plan left over.
3. Gate: `relikey-agent status -file <shadow>/status.json -max-streak 2` exits 0 for the whole soak window (24 hours on
   the canary edge), and its `bundles_refused` equals the enforcing agent's. Then switch the canary to the new version
   in enforce mode, watch its status for another window, and only then roll it to the other edges.
4. A non-empty streak is a disagreement: read the shadow's plan (`relikey-agent plan`) and its drift before anything.

## Assurance
| Check | What it proves |
|---|---|
| KeyClerk conformance (`testdata/edge.json`, KeyClerk v0.26.3 (cfc5793, signed tag; sha256 5a2c03be...): 126 cases and 8 e-mail answers: 70 verifier with live leases, visit leases, governed roles and stored state; the families statements 10, ceilings 6, ended 6, unlock 5 (both sides reach one code), module_bytes 3, requests 8 (the signed bytes for every case, the header byte for byte where accepted, the long-poll query included); the ceiling policy cases) | the same verdicts and state as the reference, no exceptions |
| interop with KeyClerk's CLI (2026-10-24) | a statement made and officer-signed by `edge_cli`, cosigned by `relikey-agent cosign`, is accepted by KeyClerk's `unseal_multi` |
| 18 canonical cross vectors, signed-request vectors | byte-exact encoding and headers |
| `regen.py <keyclerk> <tag>` | vectors rebuilt from the pinned tag; v0.19.0, v0.21.2, v0.22.0, v0.23.0, v0.26.3 |
| every mutant killed (`mutants.py`, the count grows with the guards) | every guard is caught by a test (0.23.0 added exact sealed members, canonical base64, the bound ended notice, exact statement signers and signatures, modules by hash, module bytes, unlock fields; 2026-10-25 added the governed roles: reported, ungoverned and expired grants left out, a malformed file or bundle member refused, the clerk's catalogue used) |
| randomised convergence test (200 steps, with faults) | the plan always converges, never touches unmanaged users |
| 10 end-to-end agent tests on the fakes | revocation, offline lease end, replay, ended edge, an ended notice for another enrolment key ignored, module fetched once by hash, shadow, restart, ceiling |
| `go test -race -shuffle=on` on linux/amd64 and linux/arm64 | no data races |
| the full suite natively on arm64 and on armv7 under qemu-user | the three shipped targets pass |
| fuzzing: canonical JSON 19.4M executions (15 min), the bundle verifier (15 min), the planner 6M (90 s) | no crash, no invariant broken |
| e2e stage 1 (the lab harness (kept with the maintainer)) on Warpgate v0.30.0 and a real KeyClerk v0.22.0 desk | 8/8: apply, recorded session, desk outage, revoke closes the session in 4.5 s |
| e2e stage 2 (the lab harness (kept with the maintainer)) with Keycloak 26.8.1 | 7/7: a leased person signs in, an unleased one is refused, revoke ends sign-in |
| the edge pod (`deploy/edge`, the lab harness (kept with the maintainer)) | install, compose up, the containerised agent applies, status page, gate healthy |
| staticcheck, govulncheck, vet on four targets | clean |
| soak (`cmd/relikey-soak`, below) | safety, liveness and no leaks under churn and faults over time |
| red team (`a review record kept with the maintainer`) | 22 findings; status below |

## Soak
`relikey-soak -agent ./relikey-agent -minutes N -out DIR` runs the real binary against the fakes with 20 users,
leases of 5 to 90 s, withdrawals and revocations, sign-ins, and faults (desk down, desk replaying the previous bundle,
Warpgate 30% errors, Warpgate down). The fake Warpgate ignores expiry, so every lease end is the agent's doing. Every
second it checks **safety** (no role or session outlives its leases by more than 12 s, a bound moved only by faults
that make removal impossible: Warpgate failing, or a withdrawal the desk could not deliver; a lease's own `until` is
never excused), **liveness** (a lease granted more than 12 s ago with time left is held) and that the unmanaged
break-glass user is untouched; every 10 s it samples RSS, goroutines, heap and descriptors. Pass: no violations, and
no growth beyond 25% RSS / 50% heap, goroutines, descriptors from the second to the last quarter.

Results (a Linux amd64 lab host, 2026-10-23):
| Run | Build | Minutes | Grants | Faults | Safety | Liveness | RSS (growth) | Goroutines | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| 1 | before the red-team fixes | 35 | 1069 | 57 | 34* | 0 | 15 MB (-3%) | 8 | *harness: chained desk outages not credited; every case in an outage |
| 2 | red-team fixes (a0d287e) | 30 | 913 | 50 | 0 | 0 | 14 MB (+0.5%) | 8 | pass |
| 3 | latest build, chained fault windows | 20 | 560 | 36 | 0 | 0 | 15 MB (+1%) | 8 | pass |
| 4 | the MVP build (status page, KeyClerk 0.22.0) | 45 | 1331 | 80 | 0 | 0 | 15 MB (+0.3%) | 8 | pass |
A one-minute local smoke run first found a real bug (a session left open after its user was deleted), fixed before
run 1 (2f5b718).

## Red team status
The agent's red team (2026-10-23, findings AG-1 to AG-22) is answered: each fix carries a test and is listed in the
CHANGELOG; AG-11 (a lease's role reaches only the targets the lease names) is enforced since 2026-10-25, fail closed.
Two items are engineering rather than security: AG-14 (write state only when it changes, to spare flash) is done
since 2026-10-27, and AG-20 (shadow and enforcing agents use separate enrolment keys, the procedure above).

KeyClerk 0.22.0 sends the verified e-mail on each lease (KC-10) and a stable `from` (KC-11); 0.23.0 seals the ceiling, names modules by hash and binds the ended notice. Metrics: `metrics.prom` (Prometheus text) beside `status.json`, health status-only (`relikey-agent status`), in KeyClerk's monitoring shape; OCSF log events wait for KeyClerk's decision 0018 to be published. Not yet built: the signed policy modules in wazero (the ceiling is a Go port of
`ceiling.rego` meanwhile), the LDAP facade and lease credentials, offline levels, evidence, TPM. Not yet run: armv7 on real hardware (qemu-user only so far).

## Changelog
- 2026-10-25: long-poll for the bundle (KeyClerk decision 0026): grants and revokes in seconds; pulls beside the loop; the interval as the floor after an unchanged immediate answer; KeyClerk's request vectors; the conformance set vendored from the public edge protocol v1.2.0 (126 cases); 61 mutants.
- 2026-10-25: monitoring events (decision 0025 point 1): CloudEvents with OCSF 1.6.0 data for the agent's changes, findings, refusals and an ended edge; 59 mutants. A test-only second emitter (`internal/testemit`, decision 0017).
- 2026-10-25: governed roles (finding 8): an unmanaged account holding one is reported, never changed; sources the edge's targets file and KeyClerk's signed `governed_roles` (decision 0025, vectors from KeyClerk main f6b6648); 118 conformance cases, 57 mutants.
- 2026-10-24: ported to KeyClerk 0.23.0 (107 conformance cases, 50 mutants, fuzzing 9.2M executions clean); enrolment CLI (statement, cosign, unlock-keygen, unlock-code); metrics.prom. Not yet: the e2e desk and soak on 0.23.0 (lab box).
- 2026-10-23: first version of the agent (slice 1 core), its tests, red team and soak; KeyClerk 0.22.0.

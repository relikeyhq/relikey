# Writing and building the edge agent in Go

Rules for `agent/` (decision 0011). Go **1.27.3** (go.dev/dl, 2026-10-23). Sources: the Go 1.24 to 1.27 release notes,
go.dev/doc/toolchain, go.dev/doc/security/best-practices, go.dev/doc/modules/layout, go.dev/doc/articles/race_detector,
pkg.go.dev for every package named below, and KeyClerk v0.19.0 (`docs/keyclerk-edge-interface.md`, `keyclerk/edge.py`,
`relay.py`, `policy_wasm.py`). Red-teamed the same day: `a review record kept with the maintainer` (GE-1 to
GE-20, all taken in). Each rule says why.

## Toolchain and module
- `go 1.27` and `toolchain go1.27.3` in `agent/go.mod`. The `toolchain` line is only a suggestion and
  `GOTOOLCHAIN=local` ignores it, so the build script **fails unless `go env GOVERSION` is `go1.27.3`**; CI uses a
  build image pinned by digest. Locally: `go1.27.3` (golang.org/dl) under your Go SDK directory
  (`$HOME/sdk/go1.27.3`, or `%USERPROFILE%\sdk\go1.27.3` on Windows).
- Module hygiene: `go.sum` committed; `GOFLAGS` set only by the build script; `GOSUMDB` on; `GOPROXY` the default, or
  `off` with `vendor/` for offline lab builds; `GONOSUMDB`, `GOINSECURE` never set.
- Agent dependencies: the standard library, `github.com/tetratelabs/wazero` (policy), `golang.org/x/sys` (boot clock,
  prctl), later `github.com/google/go-tpm` (assured profile) and `golang.org/x/crypto/ssh` (carried-lease proof of
  possession). Anything else needs a reason in the commit.
- **Developer tools live in a separate module** (`agent/tools/go.mod`, run with `go tool -modfile=tools/go.mod`):
  tool directives take part in version selection and would otherwise move the versions the agent links.
- Layout: `cmd/relikey-agent` plus `internal/...`.

## Build
- `CGO_ENABLED=0 go build -trimpath -buildvcs=true -ldflags="-s -w -buildid=" ./cmd/relikey-agent` for linux
  `amd64`, `arm64` and `arm` with `GOARM=7,hardfloat`. `GOAMD64`, `GOARM` and the flags are fixed in the build script
  (they are recorded in the build info).
- **Targets are those three only.** Many switches run MIPS or PowerPC SoCs: not supported until the policy runtime is
  tested there (0011, footprint).
- Release builds come from a clean tagged checkout; the script refuses `vcs.modified=true` and a `+dirty` version
  (stamped since 1.24). Reproducibility is checked, not assumed: two clean checkouts, two builds, identical bytes.
- `go version -m` output is **build info** (provenance), not an SBOM; a CycloneDX SBOM is produced separately when one
  is promised, together with the image and the policy modules it cannot see.
- Do not set `GOMAXPROCS` (container-aware since 1.25). Green Tea GC is the default and the 64-bit heap base is
  randomised since 1.26.
- Image: `scratch` or distroless static; numeric `USER 65532:65532` (no `/etc/passwd`); read-only root; all
  capabilities dropped; `no-new-privileges`; the state directory the only writable mount. No tzdata, `/etc/hosts` or
  `resolv.conf` unless mounted: format times in UTC and never load a location.

## Checks on every change
- `gofmt`, `go vet`, staticcheck, `go fix` modernizers reviewed.
- `go test -race -shuffle=on ./...` on amd64 with `CGO_ENABLED=1` (the race detector needs cgo and has no linux/arm),
  **and** `CGO_ENABLED=0 go test -shuffle=on ./...` on amd64, arm64 and armv7 (hardware, or qemu-user as a minimum):
  the shipped program is the static one, and 32-bit has its own bugs.
- `govulncheck` on the source (reachability) and on the released binary; it says nothing about the policy modules,
  Warpgate or the image, which are scanned on their own.
- Fuzzing of every parser and verifier with a committed corpus, and **differential fuzzing against the Python
  reference**: the same mutated objects to `keyclerk.edge.unseal` / `verify_bundle` and to the Go verifier; any
  disagreement fails.
- Mutants (`agent/mutants.py`): every guard removed in turn must fail a test of its package. A pull request runs the
  mutants in the files it changes and every mutant of a package whose tests or test data it changes (a weakened test
  must not escape), and all of them when it changes a shared test helper, the harness or a go.mod/go.sum; main, a
  nightly run and a manual run take the full set in parallel shards.
- KeyClerk's conformance vectors (`tests/conformance/edge.json`: 15 policy cases, 8 verifier cases) as table tests.
  They do **not** yet cover Ed25519 edge cases, canonical-JSON refusals, encodings, time strings, relay envelopes or
  unlock codes: those vectors are asked of KeyClerk (below) and the agent ships slice 1 only with them.

## Signed data (KeyClerk interface sections 2 to 4, 7)
Two signing modes, both KeyClerk's:
- **Sealed objects** `{bytes, signature, key, key_id}` (bundles, ended notices, carried leases). In this order:
  `key` equals the pinned key and `key_id` the first 16 hex of sha256 of it (compared before anything else, as
  `unseal` does); `bytes` decoded with `base64.StdEncoding.Strict()`; `signature` 128 lower-case hex; Ed25519 verified
  over the decoded bytes; the bytes parsed; **the bytes checked canonical** (`canon.Encode(parsed) == bytes`, which
  refuses whitespace, unsorted or duplicate names, escapes Python would not write, `-0`, leading zeros, fractions,
  exponents, a BOM); then `format`.
- **Embedded signed documents** (the ceiling `{document, signature}`, the enrolment statement, evidence `prev`
  hashes): the signature or hash is over KeyClerk's canonical form of the document. Verify over the document's **raw
  sub-value** (`jsontext.Value`) of outer bytes that already passed the canonical check - never over a Go
  re-marshalling.
- Where the agent writes canonical bytes itself (the statement, evidence), it uses `internal/kcedge/canon`, a
  byte-exact port of `keyclerk.edge.canonical`: names sorted by Unicode code point, `,` and `:` without spaces, UTF-8
  not ASCII-escaped, only `\" \\ \b \f \n \r \t` and lower-case `\u00xx` for other controls, integers in decimal,
  strings, bools, null, no floats. Proven by vectors both ways. **Never** `jsontext.Value.Canonicalize`,
  `ReorderRawObjects` or `CanonicalizeRawInts`: those implement RFC 8785, which orders names by UTF-16 code units and
  pushes integers through float64.
- Parse with **`encoding/json/v2`, imported explicitly**: in Go 1.27 `encoding/json` runs on the v2 code but keeps v1
  behaviour (duplicates allowed, case-insensitive names, invalid UTF-8 replaced). Never pass `AllowDuplicateNames`,
  `AllowInvalidUTF8` or `MatchCaseInsensitiveNames`; no `case:ignore` tags.
- A `jsontext.Token` is void after the next decoder call: copy `tok.String()` before reading on (found on the first
  run; it panics).
- Unknown members follow KeyClerk exactly: an exact key set for the ceiling (`CEILING_KEYS`), ignored in the bundle
  until the interface says otherwise (otherwise a KeyClerk release that adds a field bricks every edge).
- Integers into `int64` with range checks (Python ints are unbounded); JSON `true` is not a number (Python's
  `isinstance(True, int)` is a known reference quirk: vector it). Times validated against
  `^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$` before `time.Parse` (Python's `strptime` also accepts `2026-1-5T1:2:3Z`: asked
  of KeyClerk). Port Python integer arithmetic explicitly (`//` floors, Go `/` truncates) and vector negative
  durations.
- Signed requests sign exactly what is sent: `req.URL.RequestURI()` of the request as built; the body a byte slice,
  hashed once, sent with `bytes.NewReader`; nonce 18 bytes from `crypto/rand`, base64url without padding; vectors from
  `edge_cli request`.

## Cryptography
- `crypto/ed25519` plain (no `Options.Hash`, no context). `Verify` **panics** on a key that is not 32 bytes: keys are
  length-checked at pin and parse time; a panic on wire input is a bug. At pin time a key must be canonically encoded
  and not a small-order point.
- X25519 with `crypto/ecdh`; it refuses an all-zero shared secret (keep it, vector a low-order point).
- HKDF with `crypto/hkdf`: `hkdf.Key(sha256.New, secret, salt, info, n)`. Python takes salt in the constructor and the
  secret in `derive`; a swapped salt and secret is self-consistent and wrong. `kc-relay-v1`: salt `epk || recipient`,
  info `"kc-relay-v1|" + context`. Unlock (kc-unlock-v2 since KeyClerk 0.23.0): P-256 ECDH with `crypto/ecdh`, no
  salt, info `kc-unlock-v2|edge|node|desk_key|node_key`; tested against KeyClerk's unlock vectors. Both tested against `edge_cli encrypt` /
  `unlock-code` vectors, and Go-made envelopes are decrypted by `keyclerk.relay.decrypt` in CI.
- AES-GCM with `cipher.NewGCM` and a 12-byte nonce from `crypto/rand`, carried in the envelope's own `nonce` field
  (not `NewGCMWithRandomNonce`, which prepends it); context as associated data; a fresh X25519 key per envelope.
- Unlock codes: standard base32 alphabet, padding cut, 10 characters; input upper-cased; compared with `hmac.Equal`.
- Since 1.26 the random parameter is ignored for ecdh, ecdsa, rsa and dsa key generation, and `ed25519.GenerateKey`
  with nil always uses a secure source. Nothing relies on injected randomness; deterministic tests use
  `testing/cryptotest`.
- MACs and codes compared with `hmac.Equal` / `subtle.ConstantTimeCompare`. Never `math/rand` for anything
  security-relevant.

## Time (decision 0007 point 4)
- **The same rules and the same 300 s tolerance as `verify_bundle`**: refuse `now < newest - SKEW`,
  `issued > now + SKEW`, `issued < newest - SKEW`. The floor rises to max(issued, newest), from signed times only.
- All time reads go through one injected clock (wall and boottime): `testing/synctest` virtualises the `time` package
  only, not `CLOCK_BOOTTIME`.
- Elapsed time uses `CLOCK_BOOTTIME` (`unix.ClockGettime`): Go's monotonic clock and timers stop during suspend. Inside
  a container BOOTTIME can be namespaced (Linux 5.6+): note it in the footprint checks.
- **Reboots:** a changed `/proc/sys/kernel/random/boot_id` means elapsed time is unknown. On a basic edge no lease is
  live after a reboot until a fresh bundle is verified; an assured edge uses the TPM clock.
- **Warpgate's `expires_at` is a second line, never the enforcement**: Warpgate checks it against the host clock,
  which someone may set back. The agent removes role assignments and ends sessions itself at lease end, from signed
  times plus elapsed BOOTTIME. The lease loop wakes on a short tick (15 s) and recomputes; no long timers. If wall
  time and BOOTTIME-derived time disagree beyond the skew, the earlier lease end wins and is reported.
- RTC-less boards boot with a wrong clock: time sync (chrony with NTS, or the site's NTP) is an installation
  requirement. The agent never sets the clock; until it is right it refuses, saying "clock before the newest signed
  time" and what fixes it.
- `t.Round(0)` before persisting or comparing times across a process boundary.

## Applying a bundle
- The verified bundle bytes and the new floors are written in **one atomic state write before applying**;
  `applied_serial` is kept apart from the floor. A crash between the two re-applies from the stored bundle; it never
  leaves a refused serial with stale Warpgate state.
- Apply is a **convergent reconcile** from the newest verified bundle to Warpgate's observed state: removals,
  revocations and session terminations first, then grants. Every call idempotent and keyed by stable lease id;
  retried with capped exponential backoff and jitter.
- On start, reconcile from the stored bundle before the first pull.
- Shutdown: `signal.NotifyContext` for SIGTERM and SIGINT; finish the current removal batch within a grace shorter than
  the container stop timeout; never start grants after the signal; a second signal exits.
- A 410 with a sealed `kc-edge-ended-v2` is verified (this edge, and this node's enrolment key among the keys it
  ends) and ends the edge (everything removed), never retried as an outage; one naming other keys is refused. Network failure is never a reason to change state.

## State on disk
- `os.OpenRoot` confines path resolution to the state directory (symlinks cannot leave it). It does not defend
  against another process with the agent's uid, bind mounts or hard links: the directory is 0700, owned by the agent's
  uid, and nothing else runs as that uid.
- **Two slots (A/B)** with a generation counter and a checksum; read takes the highest valid generation; a write goes
  to the other slot: `Root.Create` on a temp name, `File.Sync`, `Root.Rename`, `Sync` on `root.Open(".")`. An fsync
  error fails that write: re-read and start again (Linux may drop the dirty pages).
- Write only when a floor or the applied serial changes (SD-card wear). Floors only rise: a lower value is refused.
- At start, refuse a state directory on tmpfs or overlay (statfs magic) unless configured as a lab; put it on the most
  reliable storage the host has. Unreadable state fails closed with the reason (losing floors is a reinstall).

## Network clients
- Never `http.DefaultClient`. One client per peer: dial, TLS-handshake and response-header timeouts,
  `MaxResponseHeaderBytes`, `CheckRedirect` refusing every redirect (a redirect would re-send the admin token or a
  signed request elsewhere).
- Request/response calls have `Client.Timeout`. **Streams** (Warpgate's session-approval stream) use a client without
  it, an idle read deadline renewed per event, reconnect with backoff, and a re-list after every reconnect.
- Bodies: read `limit+1` through `io.LimitReader` and refuse when exceeded (`LimitReader` truncates silently).
  `defer resp.Body.Close()` after the error check; drain what you discard.
- KeyClerk: TLS 1.3 minimum, `RootCAs` with only the pinned CA, `ServerName` set; a proxy only from the agent's own
  configuration. TLS protects the request; the signatures protect the content.
- Warpgate: `Transport.Proxy = nil`; addressed by literal `127.0.0.1` or `[::1]` matching its listener, never
  `localhost`.
- Every call has a context deadline, DNS included; DNS failure means "KeyClerk unreachable", nothing more.

## Policy modules (wazero)
- Order: verify the whole bundle (signature, canonical, format, edge, floors, ceiling); then sha256 every module
  against the signed entry (and the release manifest when pinned); **only then compile**. In-memory compilation only:
  never `NewCompilationCacheWithDir` (native code on a writable disk would be loaded without re-verification).
- Host: `env.memory` with an explicit maximum (start at 256 pages, measure), `opa_abort` and `opa_println` only;
  `opa_builtin0..4` return an error, and a module whose `builtins` export names any builtin is refused at load (as
  KeyClerk does). Reset the heap (`opa_heap_ptr_set`) before each evaluation; cap the input size; a deadline per
  evaluation with `WithCloseOnContextDone(true)`; a timeout is a refusal with its reason.
- **armv7 is outside wazero's tested matrix** (its interpreter is tested on amd64, arm64 and riscv64). KeyClerk's 15
  policy cases run under the interpreter on the reference armv7 board (or qemu-user) in CI, with evaluation times
  recorded (R-10); wazero on 32-bit stays a recorded residual until upstream tests it.

## Secrets in the process
- **Zeroing is best effort and not a control** in Go: the GC moves and copies; `runtime/secret` is experimental and
  amd64/arm64 only (on armv7 it does nothing).
- At start: `prctl(PR_SET_DUMPABLE, 0)` (no same-uid ptrace or `/proc/<pid>/mem`, no core dumps), `RLIMIT_CORE` 0,
  `GOTRACEBACK` not `crash`. No secrets in environment variables or arguments; the Warpgate admin token is read from
  a 0600 file in the state directory. Swap off or encrypted on edges holding unlock or break-glass material.
- Break-glass values are encrypted to the custodians before they touch disk; only envelopes are kept until the escrow
  confirms. On assured edges, keys are sealed to the TPM. Common TPM 2.0 parts have no Curve25519, so the X25519
  unlock key is sealed, not held natively (R-19).
- No lease ids or persons in pprof labels (1.27 prints goroutine labels in tracebacks).

## Concurrency and errors
- One goroutine owns the apply loop; others talk to it over channels. Every goroutine has an owner that cancels it;
  `errgroup` for groups.
- 64-bit counters use `atomic.Int64` (32-bit ARM needs alignment the plain functions do not give); no `int` for
  serials, wire sizes or seconds.
- Errors wrapped with `%w`, checked with `errors.Is/As`; refusals say why and what would fix it.
- `defer` in loops runs at function end: a helper per iteration. A nil pointer in an interface is not nil: return
  `nil` explicitly. Loop variables are per iteration (no `x := x`).

## Logging
`log/slog`, JSON to stdout for the host's journald, rate-limited (SD-card wear). Secret-bearing types implement
`slog.LogValuer` returning a redaction; no secret ever goes in a URL (`*url.Error` prints URLs). Log key ids and hashes,
never secrets, lease credentials, unlock codes or tokens; structured fields for lease id, serial, person key id.

## Asked of KeyClerk (before slice 1 closes)
1. Conformance vectors: the ed25519-speccheck set; canonical-JSON refusals (whitespace, order, escapes, `-0`,
   duplicates, BOM); base64 and hex forms; time-string forms; signed requests; relay envelopes both ways; unlock codes;
   `true` as a serial.
2. Validate `issued`, `from`, `until` with the regex `check_ceiling` already uses for `signed_at`.
3. Refuse a bool where an integer is expected (`isinstance(True, int)`).

## Changelog
- 2026-10-23: verifier ported (`agent/internal/kcedge`): 39 reference verdicts, 18 canonical cross vectors, 26/26
  mutants killed (`agent/mutants.py`); KeyClerk findings in `a review record kept with the maintainer`.
- 2026-10-23: first version; red-teamed the same day (GE-1 to GE-20) and rewritten: two signing modes and a canonical
  encoder, explicit json/v2, apply ordering, time and reboot rules, A/B state, streams, wazero host and armv7 residual,
  separate tools module, test matrix without and with cgo, secrets section, KeyClerk asks.

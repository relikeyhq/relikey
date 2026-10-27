# Fuzzing

ReliKey fuzzes the code that reads input it does not control, with Go's native fuzzing (`go test -fuzz`). Each target
also runs its seed corpus as an ordinary test in every `go test`, and CI runs every target for a short session on each
push and pull request (`.github/workflows/ci.yml`, job `fuzz`).

| Target | Package | What it checks |
|---|---|---|
| FuzzCompute | agent/internal/apply | the plan from arbitrary state: nothing for an unmanaged user, removals before grants, deterministic, no grant to a shared username |
| FuzzCanonical | agent/internal/kcedge | KeyClerk's canonical encoding: whatever parses re-encodes canonically, and signed bytes are their own encoding |
| FuzzVerifyBundle | agent/internal/kcedge | arbitrary signed envelopes: never a panic, never verified without the key |
| FuzzNewParsers | agent/internal/kcedge | the edge protocol's parsers on arbitrary JSON and key text |
| FuzzParseCode | fleet/internal/enrol | an enrolment code typed by a person |
| FuzzAccept | fleet/internal/enrol | an edge's enrolment presentation: taken only with the slot's secret and a signature by the presented key |
| FuzzCeremonyRoutes | fleet/internal/page | the officer and anchor ceremony requests on the fleet page |
| FuzzParseAuthData | fleet/internal/registry | WebAuthn authenticator data |
| FuzzVerifyCOSE | fleet/internal/registry | arbitrary COSE keys and signatures: never verified, never a panic |
| FuzzAssertionMutation | fleet/internal/registry | any change to a signed WebAuthn assertion is refused |
| FuzzVerifyRegistration | fleet/internal/registry | a WebAuthn registration (client data and attestation object) |

The Python tools that read input they do not control are fuzzed with Hypothesis (`tests/test_release_key.py`, the
release key tool: public key lines, Bitwarden listings and items, principals and item names). The ordinary suite runs
400 examples per target; CI's `fuzz-python` job runs 5000, and `RELIKEY_FUZZ_EXAMPLES=20000 python -m pytest -q
tests/test_release_key.py` runs longer locally.

Run one locally for longer, from its module's directory:

    cd fleet && go test ./internal/registry -run '^$' -fuzz '^FuzzVerifyRegistration$' -fuzztime 10m

A crash is saved under the package's `testdata/fuzz/`; commit it with the fix, so it stays a regression test.

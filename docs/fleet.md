# The fleet service (decision 0026)

`relikey-fleet` is ReliKey's own fleet management: it works with any clerk or none. Each edge sends a signed report of
its own state through the front's edge-facing name (model F-27); the service, on the core's loopback (F-28), keeps the
inventory and raises the silence alarm. Code: the fleet's own Go module `fleet/` (`fleet/cmd/relikey-fleet`,
`fleet/internal/fleet`), so its dependencies never enter the edge agent's; the report format and the edge's client are
`agent/pkg/fleetproto`, shared by both.

## What it holds per edge
Last seen (the service's own receive time, which it trusts for windows), the release, mode and attested profile, the
serial and applied serial, live leases, drift as reason codes (never the drift text, 0025 point 7) and the link crypto
the agent reports. State: `ok`, `silent` (no report within the silence window), or `unknown` (never reported; never
shown as last-known-good). Without a clerk the view is labelled self-reported, not attested (0026 point 1).

## The report
`{"report": base64 of the exact JSON bytes, "signature": hex Ed25519}` over `relikey-fleet-report-v1` + newline + the
bytes, with the edge's enrolment key. The context keeps a fleet report from ever passing for a clerk request
(`kc-edge-request-v2`), or the reverse. The sequence rises with every report (a replay is refused, also after a
restart) and the report's time must lie within five minutes of the service's.

## API (loopback)
- `POST /fleet/v1/report`: a signed report; 204, or 403 with the reason in the service's log only. The front routes
  this one path, POST only, on the edge-facing name (`deploy/core/Caddyfile`).
- `GET /fleet/v1/edges`: the inventory as JSON, on loopback only: never served on the edge-facing name.

## The agent's side
With `"fleet": {"url": "<the clerk's own https host>"}` in `agent.json` (the edge's `install.py` writes it), the agent
sends its report every pull interval, off its loop, over the clerk's pinned, hybrid-only client. The sequence comes
from its trusted clock, so it rises across restarts. **Read-only towards edges** (0026 point 9): the client returns
only an error, never anything the service said; any answer but 204 is a failure, its body discarded unread; the
service serves no route but the report and the view. A test pins each of these.

Events: `relikey.edge.silent.v1` when an edge goes silent, `relikey.edge.back.v1` when it reports again, as CloudEvents
with OCSF data like the agent's (0025 point 1), under the solution `relikey-fleet`.

## Packaging (R-21)
`python agent/build.py dist` builds `relikey-fleet-linux-amd64` and `-arm64` beside the agent; `install.py` builds the
image (`deploy/core/Dockerfile.fleet`: scratch, uid 10002, read-only root, no capabilities; the build context is
allowlisted by `.dockerignore`/`.containerignore`, so only the binaries reach the builder), writes
`deploy/secrets/fleet/fleet.json` with no known edges, and starts the `fleet` service in the core pod; a rebuilt image is
recreated. Each enrolled edge is made known with `python deploy/core/fleet_edge.py --edge <name> --key <its enrolment
public key>`, which writes the file atomically under a lock (the directory is mounted, so the rename is seen) and
restarts the service; an edge removed from the file leaves the inventory too. The front caps a report at 64 KB, and
refusals are logged at most once a minute per peer.

## Configuration
`relikey-fleet -config fleet.json`: `{"listen": "127.0.0.1:8093", "state": ".../fleet.json", "silence_seconds": 300,
"edges": {"plant-a": "<enrolment public key, 64 hex>"}}`. It refuses any listen address but loopback. With
`"admin": {"state": ".../admin.json", "fleet": "<this fleet's id>"}` it keeps the officer registry, the enrolment
slots and the evidence log in that file, and takes enrolment by code: presentations on the edge-facing name,
activations on the page.
`relikey-fleet -version` prints the version, the commit and the Go release, as the agent's `version` does.

## The fleet page (0026 point 13)
Operators see the inventory on a page of its own name, signed in at ReliKey's broker; no action on any edge. The page
carries no script, except for the named first officers before the fleet is anchored: the passkey steps of the anchor
ceremony need the browser's WebAuthn API, and that one script is allowed by its hash. Code: `fleet/internal/page` (`go-oidc`, `x/oauth2`, pinned in the fleet's own module, never the agent's).

- Setup: `python deploy/core/install.py ... --fleet-host fleet.example` on a fresh install (the name goes into a local
  CA's certificate), or `python deploy/core/fleet_page.py --host fleet.example` once the front's certificate names it.
  Admit an account: `python deploy/core/fleet_page.py --grant <username>` (or `--grant <username> --revoke`), or the
  clerk's governance. Without the client role the broker's sign-in succeeds and the page refuses.
- The broker client `relikey-fleet`: confidential (secret in `deploy/secrets/fleet/page.secret`, the fleet's uid only),
  code flow with PKCE, full scope off, its own client role `fleet-operator` mapped into the ID token; no realm role.
  Back-channel logout to `http://127.0.0.1:8094/backchannel-logout`, inside the pod, never through the front.
- The page checks the ID token's issuer, audience, authorised party and nonce, the state against a pre-sign-in cookie
  (one use, 5 minutes), and starts a fresh session (15 minutes, `__Host-` cookie, `HttpOnly`, `Secure`).
- The front proxies only `/`, `/callback`, `/logout`, `/slots`, the four anchor routes and the two activation routes
  on the page's name to
  `127.0.0.1:8094` (`deploy/secrets/sites/fleet.caddy`); the JSON route stays on loopback 8093.
- The page reaches the broker only: its client trusts only `ca_file` (the front's CA or chain) and dials the issuer's
  host at the front on the pod's loopback (`front`), so neither DNS nor a hairpin route matters.
- If the broker is not reachable when the fleet starts, the inventory runs and the log says the page did not start
  and why; restart the fleet once the broker is up.

fleet.json's `page` section (written by `fleet_page.py`): `listen`, `issuer`, `client_id`, `secret_file`,
`redirect_url`, `role`, `ca_file`, `front`, `officers`.

## The anchor ceremony (0026 points 16, 21, 30)
The installer names the first officers: `install.py ... --fleet-host fleet.example --fleet-officers ann,bob,cat` (or
`fleet_page.py --host fleet.example --officers ann,bob,cat`), at least three broker usernames, each holding the client
role. Then, on the fleet page:
1. Each named officer signs in and registers a passkey for fleet statements (a passkey of the page's own name, never
   the broker's sign-in). The page shows whether it is device-bound or synced. Registering again replaces it and voids
   any signatures over the old list.
2. Once all have registered, the page drafts officer list version 1 and shows its fingerprint; each officer checks the
   list and signs it with their passkey. The draft can be signed for 24 hours, then starts over.
3. With the last signature the fleet verifies the anchor whole and records it; enrolment opens.
The page holds no key and cannot complete the anchor alone; every step is in the evidence log. Registration checks:
the create ceremony, a challenge for this session used once within five minutes, the exact origin, not in a frame, the
rpId, user presence and verification, a credential id of 16 to 1023 bytes, an ES256, EdDSA or RS256 key. The
attestation statement is not trusted: officers admit officers, not authenticator vendors. Tested by Go tests with a
software authenticator, fuzzing of the registration check and of the routes, mutants for every check, and a Chromium
walk with a virtual authenticator (`fleet/internal/page/browser_test.go`, run by `build.py check` where Python
Playwright is installed).

## Enrolment by code (0026 points 15, 24, 32, 33)
1. An operator opens a slot on the page (name, kind) and gets a one-time code, shown once, carried to the edge as a
   QR code or on a USB stick.
2. The edge's installer takes the code from a file, never from the command line:
   `python deploy/edge/install.py ... --enrol-code-file <file>`, or for an installed edge
   `python deploy/edge/install.py enrol --code-file <file>`. It presents the edge's enrolment key with the code's
   secret and its own signature on `POST /fleet/v1/enrol`, over TLS that trusts only the fleet's CA, whose sha256 the
   code pins (0026 point 27): the CA is read from the chain the fleet presents and becomes the only root, the host
   name checked. The code never pins a leaf: the page makes it from `pin_ca_file`, refused unless it is a CA, so the
   leaf can be renewed without voiding codes, and the installer refuses a pinned certificate that is not a CA.
   Reading that chain needs Python 3.13 or later, so on an older Python the installer refuses enrolment and says to
   install 3.13 (Debian 13 and current Raspberry Pi OS ship it). Hybrid post-quantum key exchange is used when both
   ends negotiate it, not required: the code's secret is single use and the edge's key is public, so a recording
   decrypted later yields nothing that can still be used. Then it prints the key's fingerprint. It prints and logs
   neither the code nor its secret, and reads nothing the fleet answers but the status: 409 is "slot already taken",
   429 a retry in a minute.
3. The page lists the presented keys with their source address. An officer of the registry in force types 16
   characters of the fingerprint (80 bits; not the last 16, which carry 76 as the last character carries one bit),
   or all of it, as read from the edge's screen, records who read it and how, and signs the
   activation (up to ten slots) with their officer passkey (`/activate/begin`, `/activate/sign`; the statement is
   bound to this fleet, the registry version, the activation's hash, five minutes and a nonce, and used once).
4. The fleet verifies the signature against the registry in force and records the activation, signed, in the evidence
   log; a refusal is logged too. The slot is active and the edge's key is its report key: its first verified report
   puts it in the inventory.
Guards: the enrolment route takes at most 20 presentations a minute for the whole fleet; three refused presentations
close a slot; a second key for a used slot is refused and shown. An enrolled name cannot be opened again (a new key is
a rotation, slice 5) nor activated under a second key; a name configured in `edges` and enrolled by code under
another key is refused for both, and logged with what to do, until one is removed. Tested in Go
(`fleet/internal/fleet/enrolled_test.go`, with `deploy/edge/install.py` itself presenting where Python is 3.13 or later
with cryptography, set by `build.py check`; `fleet/internal/page/activate_test.go`; `fleet/internal/enrol`, the typed
check's 80 bits and the CA pin) and in Python (`tests/test_edge_enrol.py`, one vector shared with Go).

## The officer registry and enrolment (0026 points 14-33), the packages
- `fleet/internal/registry`: the officer registry and bound passkey statements. A statement's challenge is a hash of
  its canonical form under the context `relikey-fleet-stmt-v1`; an assertion is checked for the ceremony, the exact
  origin, the challenge, the rpId, user presence and verification, and the signature (ES256, EdDSA or RS256 COSE keys;
  an in-house check over a CBOR decoder, no WebAuthn framework). The anchor (version 1) needs at least three officers,
  each signing it; a change names the previous version by hash, takes two current officers (one device-bound),
  a majority to remove anyone, every added officer's own signature, at least three officers after, and takes effect
  after 48 hours or at once as break-glass by a majority with a device-bound passkey.
- `fleet/internal/enrol`: slots (24 hours, capped per fleet and per operator), the enrolment code (fleet, https
  address, CA pin, anchor hash, slot, single-use secret), the edge's presentation (its key, the secret, and its
  signature over the fleet, slot and commitment) with a second key for a used slot refused and recorded, and
  activation by one officer's passkey over the activation's hash: at most ten slots, each with its whole fingerprint,
  a typed check of 80 bits from the edge's screen (16 base32 characters, not the last 16, or the whole fingerprint),
  and who read it and how; a relay or site fleet only with the approver reading its screen on site.

## Not built yet (0026's slices)
The core installer's part of enrolment (fleet.json's `admin` section and the page's `enrol_url` and `pin_ca_file`;
the fleet refuses to start with the one and without the others), the
digest pin (once releases are signed), a clerk's governance facts,
signed releases and the enforced minimum release (slice 3), staged rollout (slice 4), enrolment-key rotation (slice 5), the site relay (slice 6).

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
"edges": {"plant-a": "<enrolment public key, 64 hex>"}}`. It refuses any listen address but loopback.

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
- The front proxies only `/`, `/callback`, `/logout`, `/slots` and the four anchor routes on the page's name to
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

## The officer registry and enrolment (0026 points 14-33), building blocks
Tested packages; the registry is wired into the page for the anchor, slots are opened on the page, and activation
and the edge installer's side are not wired yet:
- `fleet/internal/registry`: the officer registry and bound passkey statements. A statement's challenge is a hash of
  its canonical form under the context `relikey-fleet-stmt-v1`; an assertion is checked for the ceremony, the exact
  origin, the challenge, the rpId, user presence and verification, and the signature (ES256, EdDSA or RS256 COSE keys;
  an in-house check over a CBOR decoder, no WebAuthn framework). The anchor (version 1) needs at least three officers,
  each signing it; a change names the previous version by hash, takes two current officers (one device-bound),
  a majority to remove anyone, every added officer's own signature, at least three officers after, and takes effect
  after 48 hours or at once as break-glass by a majority with a device-bound passkey.
- `fleet/internal/enrol`: slots (24 hours, capped per fleet and per operator), the enrolment code (fleet, https
  address, pin, anchor hash, slot, single-use secret), the edge's presentation (its key, the secret, and its signature
  over the fleet, slot and commitment) with a second key for a used slot refused and recorded, and activation by one
  officer's passkey over the activation's hash: at most ten slots, each with its whole fingerprint, at least 16 typed
  base32 characters from the edge's screen, and who read it and how; a relay or site fleet only with the approver
  reading its screen on site.

## Not built yet (0026's slices)
The digest pin (once releases are signed), a clerk's governance facts,
signed releases and the enforced minimum release (slice 3), staged rollout (slice 4), enrolment-key rotation (slice 5), the site relay (slice 6).

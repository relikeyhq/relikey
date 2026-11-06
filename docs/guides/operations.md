# Run it: upgrade, back up, rotate

Day-2 tasks for an installed core and edges. Each section says what the repository supports, how to check the step
worked, and, where nothing supports it yet, what you can copy by hand and what is not covered. The commands use podman;
with docker, say `docker compose` and give `--engine docker`. Concepts are in the [overview](overview.md); messages
are in [troubleshooting](troubleshooting.md).

## Watch it
**An edge.** The agent writes its status to the state directory and logs JSON lines on standard output.

    podman compose -f deploy/edge/compose.yaml exec agent /relikey-agent status -file /var/lib/relikey/status.json
    podman compose -f deploy/edge/compose.yaml logs agent
    podman compose -f deploy/edge/compose.yaml cp agent:/var/lib/relikey/status.html .

`status` prints `status.json` and exits 1 when the edge is unhealthy, naming each cause and what fixes it. It is the
canary gate (`-max-streak`, `-max-age` tune it). `status.html` is a page for the control room; it refreshes itself every
15 seconds and the agent serves nothing, so you copy it out or serve it yourself.

**Metrics and alerts.** The agent writes `metrics.prom` beside the status and, with `metrics_dir` set in `agent.json`,
a copy for a collector. The metric names, the node_exporter recipe and seven alerting rules
(`deploy/edge/relikey-agent.rules.yaml`: silent, unhealthy, bundle refused, action failed, cannot read Warpgate, pulls
failing, ended) are on [the agent page](../agent.md#metrics). Alert at least on silence and refused bundles.

**The core.** `podman compose --env-file deploy/secrets/core.env -f deploy/core/compose.yaml ps` shows each service and
the desk's health check (`/readyz`: the store is open and the reconciler has run recently). The fleet service keeps an
inventory of enrolled edges and raises the silence alarm for an edge that stops reporting: see [the fleet](../fleet.md).
An edge silent at the core is alerted there; an agent that cannot reach the core is visible only on the edge.

## Upgrade
Not yet covered: a tested upgrade path between releases, a rule for the order of core and edges, and a rollback. What
exists is below. Read `CHANGELOG.md` for the release first; a change that needs action on your side is under Changed or
Removed. Check the release as the README's "Verifying a release" shows, and use the same checkout on every host.

**The core.**
1. Back up ([below](#back-up-and-restore)).
2. Check out the release. If you run the fleet, build its binary: `python agent/build.py dist`.
3. Run the core's installer again with the arguments you used the first time (the same names, `--keyclerk-src`). It
   keeps every secret it finds, rebuilds KeyClerk from the signed tag the release pins, and never recreates what runs
   (`up --no-recreate`, so podman is not asked to replace a container whose namespace others share).
4. Apply a changed configuration to a running service on purpose, one service at a time:

       podman compose --env-file deploy/secrets/core.env -f deploy/core/compose.yaml up -d --force-recreate <service>

   not the `front` (the others hold its namespace): for that, `down` and `up -d` (the volumes stay unless you pass `-v`).
   A later plain `up -d` may fail with "has dependent containers": use `up -d --no-recreate`. This is from
   [the core's README](../../deploy/core/README.md#on-podman), measured on podman 4.8.
5. Check: `ps` shows every service up, the edge-facing name still answers
   (`curl https://edge.example/api/v1/edge-key`), and each edge's status is healthy within a few minutes.

**An edge.** Roll one edge first, as a canary, as [the agent page](../agent.md#canary-shadow-mode-and-the-gate) describes
(a shadow agent with its own state directory and enrolment key, gated by `relikey-agent status -max-streak 2`), then the
rest.
1. Check out the release, build the binaries (`python agent/build.py dist`) and rebuild the agent image:
   `podman compose -f deploy/edge/compose.yaml build agent`.
2. The agent refuses an `agent.json` with a key it does not know, and says what to rename. Compare your file with the
   release's [agent.json reference](../reference/agent-config.md) before you start the new agent.
3. Recreate the agent: `podman compose -f deploy/edge/compose.yaml up -d --force-recreate agent`. If the release changes
   Warpgate's or the front's pinned image, `down` and `up -d` the pod instead (the volumes stay unless you pass `-v`);
   the edge's members share one namespace, as the core's do. This is not measured on the edge.
4. Check: `relikey-agent status` exits 0, `status.json` shows the new `version`, `bundles_refused` has not grown, and
   the log has a `relikey.agent.started.v1` event with the version and mode.

The compose file builds the image as `localhost/relikey-agent:dev`, so a rebuild replaces the previous tag. To keep a way
back, keep the previous release's `agent/dist/` and a copy of its image. A rollback is not tested: the agent's replay
floors only rise, and a state directory written by a newer agent is not promised to load in an older one.

## Back up and restore
Not yet covered: there is no backup or restore tool, no tested restore, and no schedule. What follows is what to copy,
taken from what the installers and compose files write. Stop the pod before copying a volume
(`podman compose ... stop`, then `start` to bring the same containers back).

**Copy for an edge** (small):
- `deploy/secrets/`, with owners and modes kept (the files are 0600, and the agent runs as uid 65532). Above all
  `enrolment.key`: the desk and the fleet know this key, a new one means the edge is enrolled again, and the agent says
  "restore the enrolment key from the edge's backup". Also `agent.json`, `warpgate.token`, `warpgate.pin`,
  `governed-roles.json`, `desk-ca.pem` if present, `lldap.env`, `warpgate.env`, the front's certificate files.
- The volumes `relikey-edge_agent` (the replay floors and the verified bundle), `relikey-edge_warpgate` (Warpgate's
  configuration and certificate, which the agent pins) and `relikey-edge_facade`.
- `deploy/edge/targets.yaml`, your own file: the roles and targets, which `targets.py` re-applies.

**Copy for the core:**
- `deploy/secrets/`, with owners and modes kept (the files KeyClerk reads belong to uid 10001, the fleet's to 10002).
  Above all `records.key` and `records.pub`, `core.env`, `front.crt` and `front.key`, `front-ca.crt` if a local CA made
  them, the broker's database password and `fleet/`.
- The volumes `relikey-core_broker-db` (the broker's PostgreSQL), `relikey-core_broker`, `relikey-core_signer`,
  `relikey-core_desk` (the signed records and log), `relikey-core_reconcile`, `relikey-core_fleet` (inventory, officer
  registry, enrolment evidence), `relikey-core_mirror`, `relikey-core_front-data` and `relikey-core_front-config`.
  Copy them with your engine's volume tooling (for podman, `podman volume export`), at one moment, with the pod stopped.
- Keep the backup somewhere other than the host, and treat it as secret: it holds the records key and the enrolment keys.

**Restore.** The code supports these facts, and nothing more:
- The agent refuses to start when its state is unreadable in both slots, and says to restore the state directory from a
  backup or re-enrol the edge. Restoring the agent's volume returns the replay floors to the backup's values; the next
  verified bundle raises them.
- A lost `enrolment.key` cannot be recreated: a new key is generated with `install.py --re-key` (below), and the edge
  is cut off until it is enrolled again at the desk and the fleet.
- The core's installer keeps every secret it finds, so the same secrets directory plus the volumes, then
  `up -d --no-recreate`, starts the same core. A restore has not been walked; do it once on a spare host before you
  need it. KeyClerk's desk has a restore mode of its own (it answers 503, which the agent treats as an outage: leases run
  on their horizons); the procedure is in KeyClerk's documentation.

## Rotate keys and certificates
A rotation has three parts: make the new one, move every place that pins the old one, and check. The table says where
each thing is pinned. What the repository gives you is below it, and what it does not.

| Thing | Pinned or used in | Procedure |
|---|---|---|
| The edge's enrolment key | the desk, the fleet, the edge | [below](#the-edges-enrolment-key) |
| The desk's certificate (the core's front) | each edge's `agent.json`: `clerk.ca_file` or `clerk.pin_sha256`; fleet enrolment codes pin the CA | [below](#the-cores-front-certificate) |
| Warpgate's certificate on an edge | `bastion.pin_sha256` in `agent.json`, `deploy/secrets/warpgate.pin`, the edge front's `warpgate.crt` | not covered |
| The edge's Warpgate client secret at the broker | `deploy/secrets/warpgate-<edge>.secret`, Warpgate's configuration | not covered |
| The desk's bundle key and the edge officer's key | `pins.bundle_key`, `pins.officer_key` in `agent.json` | not covered |
| The records key | the core's `records.key` and `records.pub` | not covered |

### The edge's enrolment key
The desk starts it (KeyClerk's `rotate_edge`) and the agent follows. The steps, the log lines and the crash safety are in
[the agent page](../agent.md#running-it) ("Rotating the enrolment key"); in short:
1. On the edge, make the next key in the directory of `enrolment_key_file`:
   `relikey-agent keygen -out <dir>/enrolment.next.key` (it prints the new key for the desk's officer).
2. The officer starts the rotation at the desk with it; the edge co-signs the statement with
   `relikey-agent cosign -in rotation.json -out rotation.signed.json -key <dir>/enrolment.next.key`.
3. Put `next_enrolment_key_file` and `rotation_statement_file` in `agent.json`, restart the agent, and let the desk's
   security officer complete the rotation.
4. With a fleet, an officer approves the handover on the fleet page.

**Check:** the log says `the desk took the next enrolment key: it is the edge's enrolment key from now on`, the status is
healthy, and the old key's file (`enrolment_key_file` plus `.old`) is deleted once the fleet takes the new key.

**Not covered in the stock pod.** The edge pod mounts `enrolment.key` as one read-only file at `/etc/relikey/`, and the
agent must swap keys with one rename inside that file's directory. As installed, the agent cannot do that. Rotating there
needs the key in a directory the agent can write (the state volume, say) and `enrolment_key_file` pointing at it; the
repository does not describe that change yet, so try it on a test edge first. A rotation that also changes the edge
officer is refused: that edge is enrolled again.

### The core's front certificate
The front's certificate is the file `deploy/secrets/front.crt` with its key `front.key`.
- **Your own certificate.** Run the core's installer again with `--cert` and `--key` (the same other arguments). It
  rewrites those two files and keeps everything else. With `--fleet-host`, the file must hold the certificate followed by
  its issuing CA, or enrolment by code stays off and the installer says so. Then restart the front so it reads them.
  Whether `restart front` is enough on your engine is not measured here (the other services share the front's namespace);
  the `down` and `up -d` path from [the core's README](../../deploy/core/README.md#on-podman) is the documented one.
- **What the edges need.** An edge that checks the desk by CA (`clerk.ca_file`) keeps working when the new certificate has
  the same issuing CA. An edge that pins the certificate (`clerk.pin_sha256`) refuses the new one: edit the pin in its
  `agent.json` and restart the agent. The installer prints the new pin. Fleet enrolment codes pin the CA, so a renewed
  leaf does not void them; a different CA does (re-run `python deploy/core/fleet_page.py --host <name>` and open new
  slots).
- **The local CA.** The installer's local CA lasts ten years and its leaf 825 days. Re-running the installer keeps the
  existing `front.crt`, so it does not renew the leaf. Not covered: to renew a local leaf, supply a certificate with
  `--cert` and `--key`.

**Check:** the edge-facing name answers `/api/v1/edge-key` with the same bundle key as before, and every edge's `pulls_ok`
keeps rising with `pulls_failed` flat.

### Other keys and the cut-off option
- `python deploy/edge/install.py ... --re-key` over an installed edge makes a new enrolment key and Warpgate admin token
  at once. The edge is cut off until it is enrolled again: use it after a loss or a compromise, not for routine
  rotation. Without `--re-key` or `--enrolment-seed-file` the installer refuses to run on an installed edge.
- The broker's bootstrap admin and the first people's temporary passwords are one-time: see
  [the core's README](../../deploy/core/README.md#after-install).

## Change what an edge reaches
Edit `deploy/edge/targets.yaml` and run `python deploy/edge/targets.py deploy/edge/targets.yaml` again. It creates or
updates the roles, targets, bindings and pinned host keys in the file and rewrites the governed-roles list. Not covered:
it does not remove a target or role that you took out of the file; remove it in Warpgate's own interface. Bind each role
only to the targets its leases name: the agent refuses to assign a role that reaches a target the lease does not name.

## Add or remove an edge
- **Add:** `add_edge.py` on the core, then the edge's installer, enrolment and `targets.py`: the install guide's steps
  [2 to 5](install.md#2-register-the-edge-at-the-broker).
- **Make it known to the fleet:** `python deploy/core/fleet_edge.py --edge <name> --key <public key>`; `--remove` forgets
  it (the inventory drops it too).
- **End it:** the desk ends an edge (KeyClerk). The agent verifies the sealed notice, removes all access and stays ended:
  to use that edge again, enrol it again. Not covered: removing the edge's client at the broker.

## A spare node (decision 0028)
A site that wants a second box gets a warm spare: a second node of the same edge that keeps its verified bundle
current and changes nothing, until an operator on site makes it the active node. It takes over by hand, in minutes;
automatic failover is designed (0028 option A) and built only when a site needs it.

**Set it up**
1. On the active node, make the site keys once: `python deploy/edge/install.py site-keys --out <dir>` (a new SSH host
   key for the site, and the front's certificate and key). Apply them there: `python deploy/edge/install.py site-keys
   --apply <dir>`, then `podman compose -f deploy/edge/compose.yaml up -d --force-recreate warpgate front`. People's
   SSH clients see the host key change this once; tell them the new fingerprint the command printed.
2. Install the spare as any edge (the install guide), with the same `--edge`, `--warpgate-url` and SSO client secret,
   and `--site-keys <dir>`: it then shows people the same host key and certificate. Its enrolment key is its own.
3. Enrol the spare's enrolment key at the desk as the edge's second node (KeyClerk: the officer's statement names two
   nodes). Do not add it to the fleet yet: the fleet takes one key per edge (decision 0026 point 15).
4. Put the spare's agent in shadow mode (`"mode": "shadow"` in its `agent.json`) and start the pod without the site's
   address: it pulls and verifies the edge's bundles and keeps its floors, and changes nothing in its Warpgate. A
   spare kept switched off instead grants nothing at takeover until it reaches the desk once, so on a site that can be
   cut off, keep it warm.

**Take over**
1. Power the failed node off, or take it off the network. It must not come back beside the spare.
2. On the spare: set `"mode": "enforce"` in `agent.json`, give it the site's address, and restart the agent
   (`podman compose -f deploy/edge/compose.yaml up -d --force-recreate agent`). It applies the leases of the bundle it
   holds at its first tick and pulls a newer one when it reaches the desk.
3. On the core: `python deploy/core/fleet_edge.py --edge <name> --key <the spare's enrolment public key>`, so the fleet
   takes its reports.
4. The failed node, once repaired, returns only as the spare: shadow mode, without the site's address.

Not covered yet: the takeover's report to the desk. The agent's `promote` command, which checks the site key's
promotion statement and reports a break-glass activation (edge protocol 1.5), comes with the agent's protocol 1.5
release. Until then the desk sees the spare's node start reporting, and the takeover is recorded by the operator.

## Stop and start
Stopping an edge makes the system behind it unreachable. Stopping the core leaves open leases running to the bundle's
horizon and holds new sign-ins and grants. Use `podman compose ... stop` and `start`, not `down`, to keep the same
containers.

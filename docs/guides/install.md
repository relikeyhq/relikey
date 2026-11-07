# Install ReliKey at a site

Stand up a core and one edge on real hosts, enrol the edge, and see one lease applied end to end. Read the
[overview](overview.md) first if the words core, edge, desk and agent are new. Everything here comes from the installers
in `deploy/` and the pages they link; where a step is not yet walked on a deployed site, it says so.

ReliKey is early (README, Status). This guide gets a working installation. It does not give you high availability or a
production network design.

The commands use podman. With docker, give `--engine docker` to the installers and say `docker compose` for the
compose commands.

## Before you start
Decide, and write down who signs each one, before you run anything:
- The [installation checklist](../installation-checklist.md): every network path to the legacy system, the edge's place,
  who holds the edge officer's key. An edge goes live only when the checklist is met or its gaps are recorded risks.
- **People.** A root holder, a security officer and an edge officer, three different people with different e-mail
  addresses (the installer refuses duplicates). The edge officer is not a core administrator.
- **Hosts.** One for the core, one per edge. Linux with podman or docker and compose, and Python 3.11 or later with
  PyYAML and `cryptography` (the installers import them). An edge's host is a switch's container host or a small
  board: the agent is built for linux amd64, arm64 and armv7.
- **Compose.** `podman compose` hands the work to a compose provider. With rootless podman and docker's compose as the
  provider, the installing user needs podman's socket running and to stay logged in for services
  (`systemctl --user enable --now podman.socket`, `loginctl enable-linger <user>`). Use compose v2.24 or later:
  check `docker-compose version`. Some cloud images ship an older one (v2.15) that fails on the services sharing the
  front's network; set `PODMAN_COMPOSE_PROVIDER` to a current one, such as Ubuntu's `docker-compose-v2`.
- **Names.** Three DNS names for the core that resolve from people and from every edge: the broker's, the desk's and the
  edge-facing one, each different (for example `id.example`, `desk.example`, `edge.example`). An optional fourth for the
  fleet page. One for each edge's Warpgate that people can reach.
- **Certificate.** One certificate and key covering the three names (and the fleet page's), as PEM. Without them the
  installer makes a local CA and a leaf; that is fine to start with, and the CA file then travels to every edge. With
  your own certificate, put the issuing CA after the certificate in the file when you want enrolment by code
  ([the fleet](../fleet.md)).
- **Ports.** The front answers on 443 (`--port` changes it). Rootless podman binds no port below 1024: use a higher
  `--port`, or let the user bind low ports. An edge publishes 2222 (SSH) and 8888 (HTTPS).
- **KeyClerk source.** A clone of `github.com/keyclerk/keyclerk` with its tags: the installer builds the pinned release
  from its signed tag and refuses a tag whose signature or commit differs.

Get the release you will run, check it, and use the same release on every host, in a checkout of its own for each
component: the core and an edge write files of the same names into `deploy/secrets/`, so the installers refuse a
directory that holds the other's (on a one-box lab, put the edge in a second directory). The README's "Verifying a release"
shows the checks (signed tag, checksums, provenance). Then on a host with Go (the version `agent/go.mod` names):

    python agent/build.py dist

This builds the agent (and the fleet service) binaries into `agent/dist/`. The edge's image and the core's fleet image
are built from there: the core installer builds and starts the fleet service only when `agent/dist/` exists, so run
this on the core host too if you want the fleet. (A release's binaries carry the same file names as the ones the
image build reads, `relikey-agent-linux-<arch>`; using them instead of building is possible but not yet walked.)

## 1. Install the core
On the core host, from the repository root:

    git clone https://github.com/keyclerk/keyclerk ../keyclerk
    python deploy/core/install.py --broker-host id.example --desk-host desk.example --edge-host edge.example \
        --root "First Last <root@example>" --officer "First Last <officer@example>" \
        --edge-officer "First Last <edge-officer@example>" --keyclerk-src ../keyclerk \
        --cert front.crt --key front.key --engine podman

Leave out `--cert` and `--key` for a local CA. Add `--fleet-host fleet.example --fleet-officers u1,u2,u3` for the fleet
page (at least three broker usernames). Never add `--lab`: it puts the pod on the host network and is for a one-box lab
only. A fresh desk can enrol an edge only when its seed names at least one entitlement and an edge officer who is no
administrator, so give `--entitlement ID[:RISK]` and `--edge-officer` as above; `--person` adds more people. The full flag list is in the
[commands reference](../reference/commands.md).

It writes `deploy/secrets/`, builds KeyClerk, starts the broker, sets up the realm, shows the reconciler's first run
as a dry run and asks before starting the reconciler (`--yes` skips the question). Running it again keeps every secret.

**Check it worked**
1. The reconciler's dry run on a fresh realm plans nothing: `desired 0, add 0, remove 0, findings 0`. Start the
   reconciler when it does.
2. The last lines name the broker, desk and edge-facing URLs and print **the desk's bundle key** (64 hex characters) and
   **the front's certificate pin** (and the CA file when a local CA was made). Keep both: every edge's installer needs
   them.
3. All services are up:

       podman compose --env-file deploy/secrets/core.env -f deploy/core/compose.yaml ps

4. The edge-facing name answers with the bundle key (with a local CA, trust its file):

       curl --cacert deploy/secrets/front-ca.crt https://edge.example/api/v1/edge-key

   The answer is JSON with a `key` equal to the printed bundle key. If the installer printed `not read yet`, run this
   once the desk is up.

**Then, the first people.** The root holder, the security officer and the edge officer sign in at the desk
(`https://desk.example`) with the temporary passwords in `deploy/secrets/people.json`, set their own and register a
passkey; the edge officer needs this too, as only they can set the edge's ceiling at the desk (step 4). Then
`deploy/secrets/people.json` is deleted. Make a permanent broker admin with a passkey and remove the bootstrap admin
soon: the steps are in [the core's README](../../deploy/core/README.md#after-install). On rootful docker, `fix_owners` runs for you; on
rootless podman the installer prints a note about file owners.

## 2. Register the edge at the broker
On the core, once per edge. The `--warpgate-url` is the address people will use for this edge's Warpgate, exactly as
you will give it to the edge's installer:

    python deploy/core/add_edge.py --edge plant-a --warpgate-url https://plant-a.example:8888 --engine podman

The edge name is lower-case letters, digits and hyphens. It makes `deploy/secrets/warpgate-plant-a.secret` and never
prints the secret. **Check:** the file exists and the command printed the edge's `install.py` line. Carry that file to
the edge host out of band, with `front-ca.crt` if the core uses a local CA.

## 3. Install the edge
On the edge host, from its own checkout of the same release, with `agent/dist/` built (see above). You need the bundle key and
pin from step 1, the secret file from step 2 and the edge officer's public key from the officer's own console.

    python deploy/edge/install.py --edge plant-a --desk https://edge.example --desk-pin <pin from step 1> \
        --bundle-key <bundle key from step 1> --officer-key <the edge officer's key> --engine podman \
        --sso-issuer https://id.example/realms/relikey --sso-secret-file warpgate-plant-a.secret \
        --warpgate-url https://plant-a.example:8888

Give exactly one of `--desk-pin` and `--desk-ca` (the PEM of the CA that signs the desk's certificate). With a local CA
add `--sso-ca front-ca.crt` and either `--desk-ca front-ca.crt` or the pin. Prefer the CA over the pin when you will
renew the desk's certificate: a pin names one certificate. The keys must be 64 lower-case hex characters, and the
installer says so when they are not.

It writes `deploy/secrets/` (agent configuration, enrolment key, Warpgate token), runs Warpgate's first setup in its
volume, pins Warpgate's certificate and prints **the edge's enrolment key**. Keep it for step 5.

Start the pod and apply the targets:

    podman compose -f deploy/edge/compose.yaml up -d
    cp deploy/edge/targets.example.yaml deploy/edge/targets.yaml     # then edit it
    python deploy/edge/targets.py deploy/edge/targets.yaml

`targets.py` reaches Warpgate's admin API on the pod's own loopback. With `--lab` that is the host's loopback. On
other installs, until `targets.py` enters the pod by itself, run it in the pod's network on rootless podman:

    pid=$(podman inspect -f '{{.State.Pid}}' relikey-edge-front-1)
    podman unshare nsenter -t "$pid" -n python deploy/edge/targets.py deploy/edge/targets.yaml

In `targets.yaml`, each target names its role, its SSH address and account, and **its own SSH host key, verified out of
band** (a target without `host_key` is refused). `targets.py` creates the roles and targets on Warpgate, binds them,
pins the host keys, and prints Warpgate's client keys: add each, as printed, to the target account's `authorized_keys`.
Run it again after any change to the file; it is idempotent. The roles it lists are what leases name: without them no
lease can grant access.

**Check it worked**
1. `podman compose -f deploy/edge/compose.yaml ps` lists `warpgate`, `front`, `facade` and `agent` running.
2. The agent's log shows it started (`podman compose -f deploy/edge/compose.yaml logs agent`): a JSON line of type
   `relikey.agent.started.v1`. Until the edge is enrolled the desk cannot know it, so `pull failed` lines in the log
   are expected at this point.
3. `targets.py` ended with the client keys and `governed roles: ...`.

If the installer or the agent refuses something, [troubleshooting](troubleshooting.md) has the message and the fix.

## 4. Enrol the edge at the desk
Enrolment binds the edge's enrolment key and the edge officer's key at the desk. The desk's own pages are KeyClerk's
(github.com/keyclerk/keyclerk); what ReliKey adds is the edge's side.

1. The edge officer and the edge both sign one enrolment statement. The officer makes it with KeyClerk's
   `edge_cli statement`, naming themselves by their **anchor** (`--officer op:...`, as the desk's People page shows it),
   not their username: the desk names the edge's officer by anchor and refuses any other statement as "officer differ".
   The edge's side is the agent's `unlock-keygen`, `statement` and `cosign` commands
   ([the agent page](../agent.md), "Running it"), run in the pod as the agent's user:

       podman compose -f deploy/edge/compose.yaml exec agent /relikey-agent unlock-keygen -out /var/lib/relikey/unlock.key
       podman compose -f deploy/edge/compose.yaml cp st1.json agent:/var/lib/relikey/st1.json
       podman compose -f deploy/edge/compose.yaml exec agent /relikey-agent statement -in /var/lib/relikey/st1.json
       podman compose -f deploy/edge/compose.yaml exec agent /relikey-agent cosign -in /var/lib/relikey/st1.json \
           -out /var/lib/relikey/st2.json -unlock-key /var/lib/relikey/unlock.key

   Read what `statement` prints (the edge, the purpose, each node's keys, who has signed) before you `cosign`: it checks
   that the statement names this edge's own keys, and notes an officer named by something other than an anchor.
   `cosign` signs with the enrolment key the agent's configuration names (`-key` to give another).
2. At the desk, root proposes the enrolment and the security officer approves it, each with a passkey. Enrolment is a
   high-risk change, so it applies only once root also signs it at the broker: the desk's page for the change says so
   ("your own signature"), and root's fresh sign-in there applies it.
3. The edge officer, signed in at the desk with their passkey, seals and sets the edge's **ceiling**. Name its persons
   by their anchors: a ceiling with no persons admits only low-class leases by its roles, and the agent's status then
   says so. Its classes must include every class the edge's targets need (a target carried by a privileged group needs
   `privileged`), or KeyClerk drops those leases; the [checklist](../installation-checklist.md) says where that shows.
4. Make the edge known to the fleet service on the core, by either route ([the fleet](../fleet.md)):
   - `python deploy/core/fleet_edge.py --edge plant-a --key <the edge's enrolment public key> --engine podman`, or
   - enrolment by code: an operator opens a slot on the fleet page, the code goes to the edge in a file, and
     `python deploy/edge/install.py enrol --code-file <file>` presents the key; an officer approves it with a passkey.
     This needs Python 3.13 or later on the edge. Ubuntu 24.04 ships 3.12: install 3.13 for the installing user
     only, for example with `uv python install 3.13`, and run the command with it.

**Check it worked.** Within a minute the agent has a verified bundle:

    podman compose -f deploy/edge/compose.yaml exec agent /relikey-agent status -file /var/lib/relikey/status.json

The JSON shows `pulls_ok` above 0, `serial` above 0, `bundles_refused` 0, `clerk_tls_group` set, and the command exits 0.
The log has `bundle verified`. The edge appears on the fleet page as `ok` after its first report.

## 5. Grant a lease and use it
1. At the desk, root grants a test person a membership that carries a target's role. Within a minute the agent applies
   it: `live_leases` is 1 in the status, and the log shows the account and role created.
2. The person opens `https://plant-a.example:8888`, signs in through the broker with a passkey, and opens a session to
   the target. The session is recorded.
3. End the membership. The agent closes the session and removes the account: `live_leases` returns to 0.

If step 1 does not happen, read `drift` in the status JSON or on the status page; each line says why and what to change
([troubleshooting](troubleshooting.md#the-status-and-drift-lines)).

## 6. Before you call it live
- Work through the [installation checklist](../installation-checklist.md) for the system, including the exposure test
  from outside the edge.
- Set up monitoring from [the agent page](../agent.md): the metrics file and the alert rules in
  `deploy/edge/relikey-agent.rules.yaml`. See [operations](operations.md#watch-it).
- Take the first backup ([operations](operations.md#back-up-and-restore)): the installers' secrets exist only on the
  host.

# Troubleshoot from the messages

ReliKey's messages say why something failed and what completes the task. This page lists the ones an operator meets,
as the installers and the agent print them, with what they mean and what to do. Quoted text is the start of the message
as the code writes it; the end of a message often names the file or value involved. If a message is not here, it still
carries its own next step: read it to the end.

Never paste a key, token, enrolment code or the contents of `deploy/secrets/` into an issue. A suspected weakness goes
through a private advisory (`SECURITY.md`), not a public issue.

## Where to look first
On an edge, from the repository root (podman shown; with docker, `docker compose`):

    podman compose -f deploy/edge/compose.yaml ps
    podman compose -f deploy/edge/compose.yaml exec agent /relikey-agent status -file /var/lib/relikey/status.json
    podman compose -f deploy/edge/compose.yaml logs agent

`status` prints the status and, when something is wrong, exits 1 with each cause. The agent logs one JSON line per
event on standard output; the message is in `msg` (the `Warn` and `Error` lines are the ones to read). On the core:
`podman compose --env-file deploy/secrets/core.env -f deploy/core/compose.yaml ps`, then `logs <service>`.

## The installers refuse
Each refusal happens before anything is written, unless it says otherwise.

| Message starts | What it means and what to do |
|---|---|
| `--broker-host, --desk-host and --edge-host (...): each needs a DNS name of its own` | The front tells the three names apart by name. Give three different lower-case names with a dot. |
| `.../deploy/secrets holds an edge's files (agent.json)` or `holds the core's files (core.env)` | The core and an edge were about to share one `deploy/secrets/`, where both write `front.crt` and `front.key`. Install each from its own checkout of the release; the edge's gets only `warpgate-<edge>.secret` and, with a local CA, `front-ca.crt`. |
| `give both --cert and --key, or neither for a local CA` | Pass the certificate and its key together, or neither. |
| `--keyclerk-ref is for a lab only` / `KEYCLERK_IMAGE is set in the environment: unset it` | Only a lab builds another KeyClerk. Unset `KEYCLERK_IMAGE` and drop `--keyclerk-ref`. |
| `KeyClerk v0.28.0: no good signature from the pinned key` | The KeyClerk clone is not KeyClerk's own repository or lacks its tags. `git fetch --tags` there, then `git tag -v v0.27.0` shows why. |
| `KeyClerk ... resolves to ..., not the pinned ...; refusing` | A moved tag is never built. `git fetch --tags --force` from KeyClerk's own repository; if it still differs, report it to the maintainers. |
| `... given more than once: the root holder, the security officer, the edge officer and each --person are different people` | Nobody approves their own powers. Give each role a person with their own e-mail. |
| `a privileged entitlement needs a separate admin account per person in its group` | The installer does not create admin accounts yet. Seed the entitlement as `elevated`, or add the admin accounts by hand after install. |
| `the reconciler's dry run did not pass (its output is above), so it does not start` | Nothing was written to the broker. Fix what the output names and run the installer again (it keeps every secret). |
| `this edge is already installed (... exists)` | Running again would make a new enrolment key and the desk would refuse the edge. Edit `agent.json` to change settings; to re-key on purpose add `--re-key`. |
| `--bundle-key '...': not 64 lower-case hex characters` (also `--officer-key`) | The agent would refuse to start. Give the desk's bundle key as the core's installer printed it, and the edge officer's public key. |
| `give exactly one of --desk-ca and --desk-pin` | The agent checks the desk by one of them. The core's installer printed both. |
| `--sso-issuer and --sso-secret-file go together` | Give both, from the core's `add_edge.py`, or neither. `--sso-ca` only with them. |
| `--sso-issuer needs --warpgate-url` | Give the same `--warpgate-url` you gave `add_edge.py`: the broker accepts only the return URL the core registered. |
| `--sso-issuer ...: https only` | The sign-in carries the edge's client secret. Use `https://<broker>/realms/<realm>`. |
| `--sso-ca needs the public roots beside it: pass --ca-bundle, or install certifi` | Warpgate must keep the public roots when it trusts your CA. Pass a full bundle with `--ca-bundle`, or install `certifi`. |
| `could not read Warpgate's certificate from its volume` | The agent would have no pin. Check that Warpgate's first setup above succeeded, then run again with `--enrolment-seed-file deploy/secrets/enrolment.key` to keep the key made. |
| `Warpgate's certificate names no host` | Remove the volume `relikey-edge_warpgate` so setup makes a new certificate, then run again with `--enrolment-seed-file` as above. |
| `enrolment by code needs Python 3.13 or later` | The code pins the fleet's CA and only Python 3.13 can read the chain. Run the installer with Python 3.13 or later. |
| `not a ReliKey enrolment code:` / `the enrolment code lacks the fleet's address, pin, anchor, slot or secret` | The file is damaged or holds something else. It must be one line starting `relikey-enrol-v1:`, as the fleet page issued it; otherwise ask for a new code. |
| `enrolment: could not reach the fleet at HOST:PORT with its pinned certificate` | Check the address and the network, then `python deploy/edge/install.py enrol --code-file <file>`. |
| `the fleet's certificate chain does not hold the pinned certificate` | This is not the fleet the code names, or the fleet's CA changed after the code was made. Ask for a new code. |
| `slot already taken` | Another key was presented for that slot. Tell the officer who opened it; the fleet keeps the first key. |
| `the fleet takes few enrolments a minute` | Wait a minute and run `enrol --code-file` again. |
| `the fleet refused the presentation (STATUS)` | The code may have expired, been used, or not be this fleet's. Ask for a new code; the reason is in the fleet's evidence log. |
| `no enrolment key to present; install the edge first` | `enrol` needs `deploy/secrets/enrolment.key`. Install the edge first, with `--enrol-code-file`. |

`add_edge.py`, `fleet_edge.py` and `targets.py` have their own:

| Message starts | What it means and what to do |
|---|---|
| `no deploy/secrets/core.env: run deploy/core/install.py first` | Run `add_edge.py` and `fleet_edge.py` on the core, after its install. |
| `--edge: lower-case letters, digits and dashes` | The edge name is `[a-z0-9][a-z0-9-]*`, up to 63 characters. |
| `--key: the edge's enrolment public key, 64 lower-case hex (or --remove)` | Give the public key `install.py` or `relikey-agent keygen` printed, not the file's contents. |
| `refused, nothing changed:` then `target X: host_key is missing` | Every target needs its own SSH host key, verified out of band. Nothing is trusted on first use. |
| `the agent did not apply the targets (exit N)` | `targets.py` hands the file to the agent's `targets` command in the pod; the agent's own message is the line above, starting `relikey-agent:`. If the agent is not running, start the edge (`compose ... up -d`) and read its log. `governed-roles.json` is changed only after the agent applied the targets. |
| `relikey-agent: ... warpgate METHOD PATH: 401 ...` | The admin token in `deploy/secrets/warpgate.token` is not the one Warpgate was started with (`WARPGATE_ADMIN_TOKEN` in `warpgate.env`). Both files must hold the same token. |
| `relikey-agent: ...` with a certificate or pin error | The agent sends the token only to the Warpgate whose certificate `agent.json` pins (`bastion.pin_sha256`). Warpgate's certificate changed, or something else answers on its loopback port. |

## The agent refuses to start
`relikey-agent run` checks its configuration and its files before it does anything, and exits with the reason. In the pod
the container stops and `logs agent` shows it.

| Message | What it means and what to do |
|---|---|
| `...: missing edge, state_dir, ...; deploy/edge/install.py writes a complete configuration` | `agent.json` lacks required keys. Compare it with the one the installer wrote and with the [agent.json reference](../reference/agent-config.md). Unknown keys are refused too. |
| `the "keyclerk" section is now "clerk"` / `the "warpgate" section is now "bastion" with "kind": "warpgate"` | An old configuration. Rename the section as the message says. |
| `bastion.url "...": https on 127.0.0.1 or [::1]` | The admin API is reached on loopback only, by address. Use `https://127.0.0.1:8899/@warpgate/admin/api`. |
| `mode "...": enforce or shadow` | Set `mode` to one of them. |
| `pins.bundle_key: ...; give the key as the desk operator read it out` | The pin is not a valid 64-hex public key. Take it from the desk (`/api/v1/edge-key`) or the core installer's output; the officer key from the officer's own console. |
| `.../enrolment.key is -rw-r--r--: make it 0600, owned by the agent's user` | A key or token file others can read. `chmod 0600` and give it to uid 65532; the installer does this, and rootless podman needs `podman unshare chown`. |
| `...: not an Ed25519 seed of 64 hex characters, so the agent cannot sign as this edge; restore the enrolment key from the edge's backup` | The key file is damaged. Restore it from backup. A new key means the edge is enrolled again. |
| `clerk.ca_file ... holds no PEM certificate, so the desk cannot be checked` | Give the CA that signs the desk's certificate (the core's `front-ca.crt`), or set `clerk.pin_sha256` instead. |
| `give either a CA or a certificate pin for this peer` | Set one of `clerk.ca_file` and `clerk.pin_sha256`, not both and not neither. |
| `the certificate pin is a SHA-256 in hex (64 characters)` | Fix `clerk.pin_sha256` or `bastion.pin_sha256`; `relikey-agent pin -cert FILE` prints the right value for a certificate. |
| `state directory ... is -rwxr-xr-x: make it 0700 so only the agent's user can read it` | Fix the mode, or in a container mount a fresh named volume (the image creates it 0700, owned by uid 65532). |
| `state directory ... is in memory (tmpfs)` / `... is on the container's overlay layer: mount a volume there` | The replay floors would be lost at a restart. Mount a persistent volume at `state_dir`. |
| `another agent holds this state directory` | Two agents share one state directory. Stop the other, or give each its own. |
| `the edge state is unreadable in both slots: refusing to start without floors` | Restore the state directory from a backup, or enrol the edge again. |
| `the event chain head is unreadable in both slots: refusing to start` | Restore the state directory from a backup; or remove `chain-a.json` and `chain-b.json` to start a new chain, which a verifier then sees as a break. |
| `enforce mode needs the kernel's boot id` / `enforce mode refuses a time namespace that offsets its clocks` | The agent needs the host's boot clock. Run on Linux with `/proc` mounted and without a time namespace, or use `shadow` mode. |
| `long_poll_seconds: at most 55` | Use 0 for the default, 55 at most, or -1 for plain pulls. |
| `fleet.url: https://<the clerk's own host>, no path, query or user` | `fleet.url` must name the same host as `clerk.url`. |
| `next_enrolment_key_file and rotation_statement_file go together` and its neighbours | A key rotation is half staged. Set both or neither, in the directory of `enrolment_key_file`: see [operations](operations.md#the-edges-enrolment-key). |

## The agent's log while it runs
The agent keeps working through these; each says what it kept doing.

| Message starts | What it means and what to do |
|---|---|
| `pull failed: the desk is unreachable or refused; leases already verified stay in force until they end` | The edge could not get a bundle. The `err` field says what: `keyclerk answered 401` means the desk does not accept this edge's signature (the key the desk holds for this edge is not this `enrolment.key`, or the edge is not enrolled yet); `certificate ... does not match the pinned one` means the desk's certificate changed: update `clerk.pin_sha256`, or use `clerk.ca_file`; other TLS or connect errors are the network or the desk's certificate. |
| `the peer negotiated ..., not the hybrid post-quantum X25519MLKEM768 this link requires` | The link to the desk or to Warpgate must use hybrid key exchange. Upgrade the peer's TLS stack, or look for TLS inspection in between. |
| `bundle refused; the edge keeps what it holds` | The `why` field has the reasons: [below](#bundle-refusals). |
| `the desk ended this edge: removing all access` | The desk ended the edge. Access is removed and stays removed until the edge is enrolled again. |
| `cannot read Warpgate; nothing changed this tick` | The agent could not read the bastion, so it changed nothing (fail closed). Check the `warpgate` container, `bastion.pin_sha256` and the token. Counted in `relikey_agent_observe_errors_total`. |
| `some actions failed; the next tick plans again` | A change on Warpgate was refused; `first` names it. A permanent refusal repeats every tick: read it, it names the path and the status. |
| `cannot store the verified bundle: not applied` / `cannot record the applied serial` / `cannot record the removals` | The state volume is not writable or is full. Fix that; the next pull applies. |
| `cannot write the status files` | The agent cannot write `status.json` to its state directory. Same cause. |
| `cannot write the metrics copy; leases are still applied` | `metrics_dir` is missing or not writable by uid 65532. The message says what to change; it does not affect leases. |
| `report not delivered; sent again after the next pull` / `fleet report not delivered; sent again next interval` | The desk or fleet did not take a report. Reports repeat; a lasting failure is a network or key problem as for `pull failed`. |
| `the fleet has not taken the enrolment-key rotation's handover; reports go on with the key it ...` | An officer has to approve the handover on the fleet page. |
| `the desk takes the next enrolment key, but it could not be made the edge's key` | The agent cannot write the directory of `enrolment_key_file`; see [operations](operations.md#the-edges-enrolment-key). |
| `policy module not fetched: retried at the next pull` | A policy module could not be fetched; it blocks nothing and is retried. |
| `the lease's address could not be fetched` | The agent could not fetch the person's verified address from the desk. It asks again after 15 seconds (an answer without an address, no sooner than a minute later). Until it has it, the person's sign-in finds no user. |

## The status and drift lines
`relikey-agent status` exits 1 with one or more of these (the same rules colour `status.html`):

| Message starts | What it means and what to do |
|---|---|
| `a plan has been left over for N ticks (max M)` | In enforce mode, Warpgate refuses the changes: the agent's log names them. In shadow mode the new version disagrees with the enforcing one. |
| `the status is ... old: the agent is not running its loop` | Read the agent's log, then restart it. |
| `no pull has succeeded: check the network path to the desk and the enrolment key` | See `pull failed` above. |
| `the desk ended this edge: it grants nothing until it is enrolled again` | Enrol the edge again. |

The `drift` list in `status.json` and on the status page says what the agent saw and why it did not act:

| Message starts | What it means and what to do |
|---|---|
| `role R is not configured on the bastion: lease for U not applied` | The installation creates roles and binds them to targets. Add the role to `targets.yaml` and run `targets.py`. |
| `role R reaches T, which the lease for U does not name: not applied` | A role reaches every target bound to it. Bind each role only to the targets its leases name. |
| `the targets of role R could not be read` | The agent could not read Warpgate this tick; it assigns nothing blind. Retried. |
| `lease L is outside the edge's ceiling: not applied` | The edge officer's ceiling does not allow this lease (class, hours or target). Widen the ceiling at the desk if it should be allowed: a target carried by a privileged group needs the `privileged` class. |
| `the edge's ceiling names no persons ...` | The ceiling admits nobody, or only low-class leases by its roles. KeyClerk drops the other leases at the desk, so none arrive. The edge officer seals a new ceiling naming the persons by their anchors. |
| `the edge's ceiling allows leases of at most N hours ...` | Memberships are granted in whole days, and the desk drops a lease longer than the ceiling allows, until its last N hours. The edge officer seals a new ceiling with `--max-lease-hours` of at least 24. |
| `user U exists on the bastion and is not managed by ReliKey: not touched; rename or remove it` | An account of that name already exists on Warpgate. The agent touches only the accounts it created. |
| `leases for different people share the username U: none applied` | Usernames must be unique per person. Fix it at the desk. |
| `lease L carries no e-mail: U cannot sign in through SSO` | The person has no verified e-mail at the broker. Fix it there. |
| `account A is not managed by ReliKey but holds the governed role R` | Someone gave a governed role outside a lease. It is reported, never changed: remove it on Warpgate. |
| `the bastion allowed ...: reset` | The agent found a weak Warpgate setting and restored it. Informational. `... and could not be reset` needs a person. |
| `the wall clock and the boot clock disagree by more than 5 minutes` | The agent uses the later time, so leases end early rather than late. Fix the host's time (NTP). |
| `the stored bundle no longer verifies: no access` | The stored bundle fails the pinned keys, so nothing is live. Check `pins` in `agent.json` and see [bundle refusals](#bundle-refusals). |

## Bundle refusals
The agent keeps what it holds and counts `bundles_refused`; the reasons are in the log (`why`) and in `status.json`
(`last_refusal`).

| Reason | What it means and what to do |
|---|---|
| `a wrong signer: not the pinned key` | The bundle is not signed by `pins.bundle_key`. The desk's key changed, or the pin is wrong: read the key from the desk and compare. Do not change the pin without checking where the new key came from. |
| `a bundle for another edge` | The bundle names a different edge than `agent.json`'s `edge`. Check the name enrolled at the desk. |
| `serial N is not above the floor M: an old bundle replayed` | The edge never accepts a lower serial. Ask whoever runs the desk whether it was restored or rolled back. |
| `issued in the future: refused` / `the clock is before the newest signed time seen: refused (time never goes back)` | Time disagrees between the edge and the desk. Check both clocks. |
| `leases without a ceiling: refused (fail closed)` / `a bundle without the ceiling the edge already holds` | The edge officer has not sealed a ceiling yet, or the desk lost it. The officer sets it at the desk. |
| `a ceiling older than the one held` / `the ceiling names another edge` | The ceiling is not for this edge or is older than the one held; the officer seals a new one. |
| `the policy release does not verify` / `policy module ... is not the released one` | Only with `pins.release_key` set: the module is not the one the signed manifest names. |

Other reasons name a malformed member; they say which. A refusal at the first bundle usually means a wrong pin; a refusal
later is a clock, a ceiling or a desk that moved.

## Containers and podman
| Message or symptom | What it means and what to do |
|---|---|
| `has dependent containers` on `compose up -d` | Podman refuses to replace a container whose namespace others share. Use `up -d --no-recreate`; to apply a change on purpose, `up -d --force-recreate <service>` (not the front), or `down` and `up -d`. The volumes stay unless you pass `-v`. |
| A published port below 1024 fails (rootless podman) | Rootless podman binds no port below 1024. Use a higher `--port` for the core. |
| The agent cannot read its files (permission denied) | `agent.json`, `enrolment.key` and `warpgate.token` must be owned by uid 65532, mode 0600. Rootful docker: the installer fixes them with a helper container; rootless podman: `podman unshare chown`. |
| A core service stops on the host network (lab) | In `--lab` the core's loopback ports (5000, 5432, 8080, 8091, 9000) must be free on the host. Never use `--lab` in production. |

## If it is still stuck
Open an issue at github.com/relikeyhq/relikey with the message, the version (`relikey-agent version`), what you ran and
what you expected, and no secrets. If the message told you something that was wrong or unclear, say so: the messages are
meant to be enough, and a gap is a bug.

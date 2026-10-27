# Deploying ReliKey

## The edge (decision 0012, R-03: one pod)
`deploy/edge/` runs an edge as one pod of pinned upstream images plus the agent: Warpgate (SSH and web sign-in, the
only published ports), lldap (the LDAP facade) and relikey-agent share one network namespace, so the agent reaches
Warpgate's admin API on loopback only.

    python agent/build.py dist                                  # the agent binaries for amd64, arm64, armv7
    python deploy/edge/install.py --edge plant-a --desk https://keyclerk.example --desk-ca desk-ca.pem \
        --bundle-key <hex, read out by the desk operator> --officer-key <hex> --engine podman
    # enrol the printed enrolment key at the desk; then:
    podman compose -f deploy/edge/compose.yaml up -d

`install.py` writes `deploy/secrets/` (git-ignored; 0600, owned by the agent's uid 65532), runs Warpgate's first
setup in its volume and pins its certificate in `agent.json`. The agent refuses to start on anything looser: a state
directory others can read, a key file others can read, a Warpgate address that is not loopback, a missing pin.

The edge's status page is written by the agent to `/var/lib/relikey/status.html` in its volume (it serves nothing):
`podman compose -f deploy/edge/compose.yaml cp agent:/var/lib/relikey/status.html .`. The canary gate is
`podman compose ... exec agent /relikey-agent status -file /var/lib/relikey/status.json`.

`compose.lab.yaml` (host network) is for the lab only. Proven on a lab box against a real KeyClerk desk:
the lab harness (kept with the maintainer).

## The core (decision 0015: one pod)
`deploy/core/` runs the core as one pod: Caddy in front (TLS, the only published ports), Keycloak with its PostgreSQL,
KeyClerk's desk, checking signer and reconciler, and the update mirror (zot), all on the pod's loopback.

    python deploy/core/install.py --broker-host id.example --desk-host desk.example --edge-host edge.example         --root "First Last <root@example>" --officer "First Last <officer@example>" --keyclerk-src ../keyclerk

It prints the desk's bundle key and the front's certificate pin for an edge's install.py; `deploy/core/add_edge.py`
registers an edge's Warpgate with the broker (its install.py then takes `--sso-issuer` and `--sso-secret-file`). Details, the three names
and what each serves, and what to do after install: `deploy/core/README.md`.

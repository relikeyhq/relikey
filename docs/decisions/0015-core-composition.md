# 0015: The core as one pod: Caddy in front, the broker's PostgreSQL, everything else on loopback

- Status: accepted (2026-10-24; the operator delegated the choice to the ReliKey design session, which chose option A
  of three: Caddy in the pod, the organisation's own proxy only, or HAProxy in the pod)
- Date: 2026-10-24
- Builds on: 0005 (the edge only connects out), 0010 (Keycloak and Warpgate), 0012 R-01 (no OpenBao in ReliKey),
  R-03 (a pod of pinned upstream images), R-20 (zot in the core); KeyClerk decision 0015 (the checking signer)

## Context
`deploy/edge` runs an edge as one pod. The core had no composition: Keycloak, KeyClerk and the update mirror were
named in the model but not assembled. Three facts shaped it:
- KeyClerk's desk serves plain HTTP; desk-native TLS is not planned (KeyClerk, 2026-10-24). Edges pin TLS to the
  desk, and browsers need HTTPS for the desk and the broker, so something in the core terminates TLS. No component in
  the model did.
- KeyClerk accepts plain http to the broker only on loopback (its broker URL guard), and its signer must never be
  reachable through a proxy.
- Keycloak in production needs a database; the model had none.

## Decision
1. **One pod.** The front proxy owns the network namespace; the broker and its database, the desk, the checking
   signer, the reconciler and the mirror share it and listen on loopback only. The front is the only service with
   published ports. Like the edge, the core works with `podman compose` and `docker compose`.
2. **Caddy is the front.** Pinned by digest, one TLS listener routed by host name:
   - the broker's name serves the one realm's sign-in, OIDC endpoints and keys, and its static resources; not the
     master realm, the admin console or the admin API;
   - the desk's name serves the desk and its API;
   - an edge-facing name serves only what an edge needs: the desk's edge routes (`/api/v1/edge/*`, `/api/v1/edge-key`)
     and the mirror's read API (GET and HEAD under `/v2/`). Warpgate's OIDC uses the broker's name (F-04);
   - the broker's admin console only on a listener published to the host's loopback (an SSH tunnel).
   Caddy runs without its admin API and without ACME. The certificate is install.py's (a local CA and a leaf naming
   the three names) or the organisation's own. The organisation may still put its own proxy in front.
   Why not the organisation's proxy alone: TLS for ReliKey's own desk and broker is part of being deployable and safe
   out of the box (secure by default, 0001), unlike OpenBao, which holds the organisation's existing secrets (R-01).
   Why not HAProxy: the same result needs more wiring for certificates and host routing.
3. **PostgreSQL for the broker.** `postgres:16.8-alpine`, the broker's own, on loopback with SCRAM; nothing else
   uses it.
4. **The signer on a unix socket.** The records key is mounted into the signer only. The desk reaches the signer on
   a unix socket in a tmpfs volume that no other service mounts. The reconciler gets the public half and refuses
   records the signer did not sign.
5. **Hardening as on the edge.** Every service: `no-new-privileges`, all capabilities dropped. Read-only root and a
   non-root user wherever the image allows it (the residuals below say where it does not). Secrets are generated
   into `deploy/secrets/` and never committed. Host names come from `deploy/secrets/core.env`, so the committed files
   name no deployment.

## Consequences
- The model gains two components, `front` (Caddy) and `broker-db` (PostgreSQL), and the core's loopback flows
  (F-22 to F-26). The edge-to-core flows (F-01, F-02, F-04, F-06, F-18) now reach the front on 443. The model check
  allows a loopback flow when both ends are in one tier (the edge host, or the core pod).
- **The front is a trust boundary.** One TLS terminator holds the key for the broker's name and the desk's: whoever
  holds the front can read and change sign-ins and desk traffic in transit. It holds no other secret, and the
  records stay signed end to end: an edge verifies bundles by the desk's key, not by TLS. The front is in scope for
  the full-stack test and a later review. It is not a new abstract model, so there is no red-team gate now.
- **One proxy technology across the product.** The edge's filtering proxy (0008, `proxy`, still unbuilt until
  warp-tech/warpgate#2782 lands) can use the same pinned Caddy, so one proxy image is pinned and trusted. 0011 named
  a minimal Go binary for it; when the edge proxy is built, that choice is revisited against this one.
- **Edges and a local CA.** An edge reaches two core names: the broker's (Warpgate's OIDC issuer, F-04) and the
  edge-facing one (the agent's desk URL and the mirror, F-06, F-18). With install.py's local CA, the agent pins the
  front's leaf (or takes the CA file). Warpgate's SSO client (reqwest with rustls native roots) trusts the container's
  trust store, so the edge's install.py points SSL_CERT_FILE at a bundle of the public roots plus that CA. Never the
  CA alone: the variable is process-wide, and Warpgate's other TLS clients (recording upload to S3, OpenSSL for RDP,
  public HTTPS targets) still need the public roots. This is expected to work from its build features; it is not yet
  proven on a box.
- Residuals: Keycloak runs with a writable root (`start` builds into the image's directories on first boot; a
  prebuilt optimised image would remove it). Caddy and zot run as uid 0, because their images ship no unprivileged
  user: zot with no capabilities, Caddy with NET_BIND_SERVICE only (its binary carries that file capability and does
  not start without it). The mirror listens on the pod's loopback only; its signed update manifest (C-11) is not
  built yet.
- Not yet: HA for the core (0012 HA-1, 0013), filling the mirror from a signed update manifest (C-11), approval
  proofs on the signer (`--approval-issuer`), and the console (`keyclerk.console`).
- **Proven on rootless podman** (2026-10-24, `deploy/core/README.md`): the pod stands up from install.py, the realm and
  SCIM work, the desk seeds through the signer, the reconciler's dry run is empty, and the front serves exactly the
  routes above (everything else 404). On podman, a container whose namespace others share cannot be replaced, so the
  installer never recreates running services. Docker, an edge signing in, and Warpgate trusting the local CA are the
  full-stack test's.

## Changelog
- 2026-10-24 Created.
- 2026-10-24 The podman stand-up recorded; the installer's local CA carries key identifiers.

# Architecture

The model in `model/` is the source; this page explains it. If they disagree, the model wins and this page is wrong.

```
   core (once per organisation or site, normal compute)
   +---------------------------------------------------------------+
   |  broker (Keycloak) <-F-05-- clerk (KeyClerk) --F-14--> vault   |
   |        ^      ^                  ^   (optional OpenBao)        |
   +--------|------|------------------|----------------------------+
      F-01  |      | F-04        F-06 | (edge pulls signed lease bundles; edge only connects out)
            |      |                  |
   person --+------|--------- F-02 ---' (desk)
     |             |                  |
     | F-03        |                  |
   +-v-------------|------------------|----------------------------+
   |  edge (switch container host or small board, <= half of 512 MB) |
   |   bastion (Warpgate) <-F-07-- agent --F-08--> facade (LDAP)    |
   +-----|-------------------------------------------^-------------+
         | F-10 (recorded sessions)                  | F-11 (its own bind)
         v                                           |
      legacy system (appliance, controller, robot) --'
```

## Who decides, who enforces
- **KeyClerk decides** in the core and signs leases into bundles for each edge: leases, second keys, plane rules, hours; every decision is compiled Rego run in process.
- **Keycloak authenticates**: passkeys, sessions, approval sign-ins; it holds no access rules of its own.
- **The edge agent applies** signed leases and decides nothing (decision 0005).
- **Warpgate enforces and records** for interactive sessions (P-A, P-C), streaming recordings off the edge.
- **The facade enforces** for LDAP binds (P-B), its passwords rotated by the agent per lease: outside a lease no usable password exists.

## Trust and failure
- Every edge and core component is control plane (KeyClerk 0011a): administered only by control-plane admin personas from
  privileged devices, in hours, with a second key.
- The edge down means the legacy system is unreachable (fail closed); the core unreachable means open leases run to
  the bundle's horizon and new sign-ins wait (R-09). Offline access for a person on site and
  break-glass follow decision 0006: pre-staged or carried visit leases, a phoned unlock, then sealed break-glass.
- The core's broker is a KeyClerk cell (KeyClerk 0013 D1); KeyClerk is its one writer (0013 D2).

## Open
See `model/open-decisions.yaml` (R-01 to R-13). Next steps: red team of decisions 0001 to 0006 and the model; decide
loop on R-01 to R-13; a footprint soak on the R-10 hardware; a facade compatibility test set for R-02.

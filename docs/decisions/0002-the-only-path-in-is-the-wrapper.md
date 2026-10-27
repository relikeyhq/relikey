# 0002: The only path in is the wrapper

- Status: accepted (operator, 2026-10-23: as amended by 0007, 0008 and 0009 after red team 1)
- Date: 2026-10-23
- Amended by 0008: break-glass when the edge is dead is a legacy-native escrowed account; the user HTTPS port is
  fronted by a filtering proxy.

## Context
Encapsulation means nothing if the legacy system can still be reached around the appliance. Platform designs that
use a bastion state the same rule as "the only path in is the wrapper".

## Decision
1. Every allowed flow is listed in `model/flows.yaml`; anything else is refused (default deny). The model check refuses
   a flow into the legacy zone from any component except the bastion (interactive sessions) and refuses any flow from
   the legacy zone except to the facade (its own LDAP bind).
2. A deployment proves the rule on its own network: a ReliKey check from outside the appliance must fail to reach the
   legacy system on every port (an exposure test, as in the platform's lab practice).
3. Three encapsulation patterns (`model/patterns.yaml`): P-A protocol bastion, P-B LDAP lease credential, P-C web front
   with injected identity. A deployment picks per system; P-A in front of P-B is preferred where the system's UI allows
   it, so the person never sees the lease credential.
4. When the appliance is down, the legacy system is unreachable: ReliKey fails closed. Break-glass is decision register
   R-06, not an open side door.

## Consequences
- The legacy system's network must be re-plumbed so its only neighbours are the appliance's bastion and facade. That
  is the main installation cost and is stated up front to the system's owner.
- Users of the legacy system change how they reach it (through the bastion or with a lease credential); the system
  itself is unchanged.

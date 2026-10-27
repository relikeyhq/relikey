# 0016: Solution-agnostic contracts by role, with adapters, profiles and a conformance matrix

- Status: accepted (operator, 2026-10-24, with 0023; red-teamed in the agnostic-contracts review and the behavioural
  conformance run against Teleport and midPoint)
- Date: 2026-10-24

## Context

ReliKey composes upstream components (decision 0001). Its contracts (`model/contracts.yaml`) are already stated against
*roles* - every contract has `provider: bastion | clerk | facade | broker | mirror | org-store | agent | host`, not a
product name. But each contract's `api:` binding cites a specific implementation (Warpgate's `users.rs`, lldap's
GraphQL, KeyClerk's bundle format). So the roles are abstract while the bindings are KeyClerk/Warpgate-shaped, and
nothing proves a contract does not secretly depend on a KeyClerk or Warpgate particular.

We want to be sure the contracts are solution-agnostic - that the governance role could be an IGA other than KeyClerk
and the bastion role a product other than Warpgate - while still optimising for, and shipping, KeyClerk and Warpgate.

## Decision

1. **The contract is the role's product-neutral behaviour; the binding is the adapter's.** Contracts stay keyed to
   roles and to behaviour that names no product. How a given implementation meets a contract (its API, its permission
   model) is an *adapter*, not part of the contract. The reference adapters are `keyclerk` (clerk), `warpgate`
   (bastion), `lldap` (facade), `keycloak` (broker), `zot` (mirror), `s3` (org-store).

2. **Adapters (`model/adapters.yaml`).** Per role, the implementations, each declaring which contracts it satisfies
   (and any it degrades or cannot meet, with the reason). Stand-in implementations - `other-iga-1`, `other-iga-2`,
   `other-bastion-1`, `other-bastion-2` - exist only to prove agnosticism; they meet the role interface by
   construction. Candidate real products to promote a stand-in to a named adapter when assessed: for the clerk role
   midPoint or Apache Syncope; for the bastion role Teleport or HashiCorp Boundary. We assert nothing about a real
   product's capabilities until it is assessed.

3. **Profiles (`model/profiles.yaml`).** A profile binds each swappable role to one implementation. The matrix is
   `{clerk} x {bastion}` over `{keyclerk, other-iga-1, other-iga-2} x {warpgate, other-bastion-1, other-bastion-2}`,
   plus two degraded profiles: `only-bastion` (clerk = none) and `only-clerk` (bastion = none). `reference` =
   KeyClerk + Warpgate and is the optimised, shipped profile; it must satisfy every contract.

4. **Conformance (`tools/check_conformance.py`), config-as-code.** For each profile it derives which contracts hold: a
   contract holds iff its provider role is bound to an adapter that satisfies it and every swappable role it consumes
   is bound. The reference profile must hold every contract. A contract that no stand-in can satisfy is a red flag -
   the contract was product-shaped and must be reworded. This is static/declarative conformance now; behavioural
   conformance, running a real stand-in product in a container against the contract, is a later slice (a lab box).

5. **Degradation is explicit, not failure.** `only-bastion` is a recorded protocol bastion with no lease governance;
   `only-clerk` is lease-governed LDAP access with no protocol bastion. Both are supported, reduced ReliKeys; the
   matrix states exactly which contracts each keeps.

## Consequences

- The contracts gain a second check (`check_conformance`) beside the model check; the reference profile staying
   complete is enforced.
- The edge agent stays ReliKey's own (it provides C-07..C-10); it is never a stand-in. Swapping happens at the clerk,
   bastion and infra roles.
- We keep KeyClerk and Warpgate as the only *reference* adapters and optimise for them; stand-ins are proof, not
   shipped products. We do not over-generalise the agent or the edge interface to chase a product we will not ship.

## Consider the opposite

The real risk is an adapter that lies: a stand-in that *declares* it satisfies a contract it could not in practice, so
the matrix is green but the agnosticism is fictional. Static conformance cannot catch that; only behavioural
conformance against a real product can. So this decision is proposed, not accepted, and its acceptance is gated on
(a) a behavioural conformance run of at least one real stand-in per swappable role and (b) an adversarial red team of
the model (does any contract still smuggle in a KeyClerk/Warpgate assumption?). Until then the matrix proves the
contracts are *expressible* agnostically, which is necessary but not sufficient.

## Changelog
- 2026-10-24: proposed.

# Adapters

An adapter binds a role to a concrete implementation (decision 0016). The contract
(`model/contracts.yaml`) is the role's product-neutral behaviour; how a given product meets
it is the adapter's.

These are **thin, measuring** adapters (decision 0016, option A): each is just enough to run
the role's contract operations against a live product and record whether the product meets the
neutral need - not a production integration. Their value is to convert a declared `satisfies`
into a measured fact, and to expose the **residue**: what the adapter (or the agent) must add
that the product does not give.

- `bastion/teleport.py` - the bastion role against Teleport. Measured (2026-10-24): C-01
  (time-bounded grant) maps cleanly via Access Requests; C-02 (offline edge approval) is a hard
  capability gap - Teleport approval is central-Auth-Service only; C-06 (pre-staged offline
  credential) has no Teleport equivalent (central short-lived certs). Evidence:
  `a review record kept with the maintainer`.

The reference adapters (KeyClerk for clerk, Warpgate for bastion) are the shipped, optimised
implementations; these stand-in adapters exist to keep the agnosticism claim honest.

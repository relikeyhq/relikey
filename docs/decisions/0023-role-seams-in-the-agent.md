# 0023: Role seams in the agent: the core speaks to a clerk and a bastion, not to KeyClerk and Warpgate

- Status: accepted (operator, 2026-10-24: "code like this does not feel bastion-solution-agnostic"; then "YES" to a
  short decision, the refactor, and accepting 0016 with it)
- Date: 2026-10-24
- Builds on: 0016 (contracts by role, accepted with this decision), 0017 (a neutral edge-decision interface, proposed),
  0011 (the edge agent)

## Context
0016 keeps the contracts keyed to roles (clerk, bastion) with KeyClerk and Warpgate as the reference adapters, and warns
against generalising the agent's behaviour for products ReliKey will not ship. The agent's code did not follow it:
- its core held a `*keyclerk.Client` and a `*warpgate.Client`;
- its plan code used Warpgate's types throughout;
- its configuration had `keyclerk` and `warpgate` sections.
So the role seam existed in the documents and not in the code: replacing the bastion meant editing the core.

## Decision
1. **The core speaks to roles.**
   - The agent's core holds a clerk and a bastion, typed by role interfaces.
   - The plan is computed in the bastion role's own terms: accounts, roles that reach targets, expiring grants, sign-in
     identities, keys and sessions.
   - Only the composition root (`cmd/relikey-agent`) names the products it wires in.
2. **The bastion role's interface is the reference model of a bastion that grants access by expiring roles.**
   - Its types live in a neutral package.
   - Warpgate is one adapter: it converts Warpgate's admin API to that model, and maps Warpgate's "not found" to the
     role's.
   - A bastion with another model is mapped by its own adapter, measured as `adapters/` does for Teleport. Example:
     access requests instead of grants.
3. **The clerk role is the public edge protocol.**
   - The clerk is whatever speaks KeyClerk's edge protocol, published as an open, versioned specification
     (github.com/keyclerk/edge-protocol).
   - The agent's clerk interface is that protocol's transport: pull, fetch a policy module, report.
   - Verification stays the protocol's own, against pinned keys.
   - A neutral decision interface over other clerks remains 0017's question.
4. **Configuration by role.**
   - `agent.json` has a `clerk` section and a `bastion` section with `kind: warpgate`. An unknown kind is refused.
   - A file with the old `keyclerk` and `warpgate` sections is refused with the rename it needs, never read silently.
   - Status keys are role-named (`clerk_tls_group`, `bastion_tls_group`).
5. **Proof that the seam is real.**
   - A second, deliberately different bastion: in memory, with no soft delete of grants and ids that are not Warpgate's.
     The same plan drives it to the same converged state in the tests.
   - The core packages import no product package; a test checks that.

## Consequences
- Adding a bastion is an adapter, not a change to the core; what the adapter cannot map is a stated gap, as in 0016's
  matrix.
- Lab installs re-render `agent.json` (deploy/edge/install.py writes the new sections).

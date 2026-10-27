# 0004: KeyClerk drives the bastion; Warpgate enforces and records

- Status: accepted (operator, 2026-10-23: as amended by 0007, 0008 and 0009 after red team 1)
- Date: 2026-10-23
- Amended by 0007: point 3 is wrong - visit keys need `UsersEdit`; the agent counts as a full Warpgate administrator.
- Amended by 0005 and 0007: the session decision moved to the edge. KeyClerk grants and signs leases and the policy;
  the agent evaluates that signed policy for each pending session and calls Warpgate's API on the edge's loopback.
  Points 1, 3, 4 and 5 hold with "KeyClerk" read as "KeyClerk through the agent"; point 2 now happens on the edge.

## Context
Warpgate 0.30 has per-target session approvals (since 0.29) and role assignments with an expiry, both reachable through
its admin API with scoped admin permissions (`ApproveSessions`, `AccessRolesAssign`). On its own, approval is a human
admin's click with no lease, policy or signed record.

## Decision
1. KeyClerk is the only writer of who may reach which Warpgate target: a lease becomes a role assignment with
   `expires_at` at the lease end (C-01). Assignments KeyClerk did not make are drift and are reported.
2. Targets that need a second key or hours-bound access require a session approval; KeyClerk decides each pending
   session with its compiled policy and approves or rejects through the API (C-02). Warpgate's own approval UI is not
   used by people; KeyClerk's desk is the one place to approve.
3. KeyClerk's Warpgate credential is a scoped admin role holding only `AccessRolesAssign` and `ApproveSessions`, never a
   full admin.
4. Warpgate signs people in through the broker (OIDC) only; local Warpgate passwords are off, except the sealed
   break-glass account (R-06).
5. Evidence joins up: a Warpgate session id is recorded against the KeyClerk lease and approval that allowed it.

## Consequences
- Two KeyClerk target plugins are needed (C-01, C-02), built in the KeyClerk repository.
- Warpgate's admin API had breaking changes in 0.29; the plugin pins the API version it was tested against and the
  end-to-end tests gate every Warpgate pin change.

- The agent reports a role a live lease grants that someone else removed before the lease ends, such as Warpgate's
  single sign-on role sync at a login whose roles claim lacks the role (warp-tech/warpgate#2785): a drift line per
  role, counted in the status as `roles_removed_outside`. Enforce mode grants the role again, as before.

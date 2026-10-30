# Improving the components upstream

ReliKey forks nothing (decision 0001). Where a component lacks what ReliKey needs, the first choice is to improve the
component itself, in a way that helps every user of it. Warpgate accepts AI-assisted contributions with disclosure;
ours are "Human-designed, AI-coded". Nothing goes upstream without the operator's approval of that item. Fork:
github.com/vdhome-dev/warpgate (account vdhome-dev).

## Register

| # | Where | Improvement | Why ReliKey needs it | Upstream (2026-10-23) |
|---|---|---|---|---|
| U-01 | russh (server) | Accept `sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256` for publickey sign-in | Visit leases bound to a FIDO key (0006) | Issue russh#760 open (not ours); russh#701 merged, #785 open |
| U-02 | Warpgate | SSH user certificates signed by a configured CA | Visit leases as short-lived certificates verified offline | Issues #26 (2022) and #1741 open (not ours); PR #1847 covers target certificates only |
| U-03 | Warpgate | External approver for session approvals | KeyClerk decides approvals | **Dropped**: the admin API approves and rejects, and a changes stream exists (`session_approvals.rs`); the agent uses them with a token holding `ApproveSessions` |
| U-04 | Warpgate | Serial console target behind the SSH listener | Old network equipment (0006, R-12) | Not raised; needs a design discussion |
| U-05 | Warpgate | armv7 build | Stretch footprint profile | Not raised; small CI change |
| U-06 | Warpgate | Dynamic RDP credentials from the OpenBao LDAP engine | AD account per lease | Issue #2762 open (not ours) |
| U-07 | Warpgate | An LDAP listener answering legacy binds | Would fold the facade into the bastion | Not raised; reverses Warpgate's direction - ask first, low priority |
| U-08 | Warpgate | Separate listener for the admin UI and API | Admin surface off the user port (0008) | Issue #2781; **PR #2782** (all checks green except cargo-deny, which fails on main) |
| U-09 | Warpgate | Per-user target credentials injected into RDP and HTTP targets | The person never sees a lease credential (P-B) | Not raised; builds on #2762 |
| U-10 | Warpgate | S3 recordings: failed chunks dropped; upload the scratch copy with retry | Evidence on unreliable uplinks (0009) | Issue #2788 **closed, not reproduced**: no parts were uploaded mid-session and a 45 s S3 outage left the recording intact |
| U-11 | Warpgate | Configurable desktop recording frame rate | Busy RDP at ~5 MB/s on small edges | **PR #2784** (4.5x smaller at 5 fps, measured) |
| U-12 | Warpgate | Bind SSO credentials to the IdP subject, not only the e-mail | E-mail is the identity key today (0010) | **Issue #2787** |
| U-13 | Warpgate | SSO roles claim revokes role assignments made outside SSO | A roles mapper on the IdP would wipe KeyClerk's leases (0010, lab) | **Issue #2785**, corrected publicly: only the unmapped default; `role_mappings` limits SSO to mapped roles (verified live), so a docs note may be enough |
| U-14 | Warpgate | End sessions when the role assignment that admitted them expires or is revoked | Leases end sessions without the agent's help (0008 RT-11) | **Issue #2786**, confirmed live; **PR #2789** (2026-10-23): sweep plus revoke hook, same query as admission, ticket sessions untouched; tests pass on the branch, fail on main and under mutation; released in 0.30.2 |
| - | Warpgate (housekeeping) | Bump `ctutils` for RUSTSEC-2026-0385 | cargo-deny fails on every PR | **PR #2783**; with #2775 (not ours) cargo-deny is clean |

## PR plan
Order by value to every Warpgate user, then by what ReliKey needs first; one or two of our PRs open at a time, so the
maintainer is not flooded; an issue's design is agreed in the issue before the PR when it adds a migration or a
behaviour change.

| Step | Item | Change | Effort | Gate before starting |
|---|---|---|---|---|
| 1 | U-14 (#2786) | revoke closes affected sessions; expiry sweep like tickets; cluster fan-out; e2e with an SSH session | medium | confirmed live; after #2782 is reviewed |
| 2 | U-13 (#2785) | a docs note on role sync without `role_mappings` (or `source` tracking if the maintainer prefers) | small | the maintainer's answer on #2785 |
| 3 | - | (U-10 dropped: not reproduced) | - | - |
| 4 | U-12 (#2787) | subject on SSO credentials (migration), upgrade on next login, optional `match_by` | medium | maintainer agrees on the migration |
| 5 | U-01 (russh#760) | server-side sk-* verification in russh, then a Warpgate bump | medium-high (crypto) | russh maintainer's view on #760 |
| 6 | U-05 | armv7 target in CI and Cross.toml | small | ask in an issue whether armv7 releases are wanted |
| 7 | U-02 (#26) | SSH user certificates | large | join the design discussion on #26 first |
| 8 | U-04, U-09 | serial console target; per-user credential injection | large | design issues first |

Every issue is verified live before it is raised (control and case, attacked from several angles, checked against
configuration that may already cover it). Every PR follows what #2782 established: built and tested on a lab box, a control run on main where the new tests must
fail, mutation checks for each guard, clippy and fmt clean on changed files, schemas regenerated, short comments
(Warpgate's `ai-comment-check` judges comments over 200 characters).

Workaround until U-01 lands: the operator's hardware key holds a non-exportable `ssh-ed25519` key (OpenPGP applet,
touch required), which Warpgate accepts as a plain public key.

# Installation checklist

What an installation must establish before an edge goes live, per encapsulated system. Each item is evidence the
system's owner signs off; an item that cannot be met is a recorded risk with the owner's name, never silently skipped.

## The only path in (decision 0002)
- [ ] Every network path to the system is listed. All but the edge's bastion and facade links are removed or blocked.
- [ ] The exposure test, run from outside the edge, cannot reach the system on any port.
- [ ] Non-IP paths are inventoried, each disabled or recorded as a risk (decision 0009, out of scope for ReliKey):
  - [ ] cellular or dial-up modems, vendor remote-support boxes;
  - [ ] remote-support tools on the system or its operator stations (TeamViewer-like);
  - [ ] vendor VPNs and site-to-site tunnels;
  - [ ] USB ports, serial and console cables, maintenance ports not behind the edge;
  - [ ] wireless interfaces on the system or the equipment around it.
- [ ] The edge does not run on the equipment it protects (decision 0006): for network equipment, a small board or a
  separate management switch with a console cable.

## Engineering workstations (pattern P-E, decision 0019)
- [ ] Each workstation is plant-owned, inside the system's zone, with the vendor suites licensed on it; its patching and
  hardening owner is named.
- [ ] Its conduit (which controllers and safety systems it reaches) is recorded and signed by the system owner; a
  workstation that reaches a safety system is its own entitlement.
- [ ] It is reached only through the bastion (RDP on a lease); the exposure test confirms nothing else reaches it from
  outside the zone.
- [ ] Session-start approval has at least two eligible people on site, and the local page showing live sessions is
  where the control room can see it.
- [ ] Vendors whose tools run only on their own laptop are told this work does not go through ReliKey.
- [ ] A diagnostic workstation (decision 0020) has its read-only conduit recorded: the enforcing device or replica,
  the allowed functions and addresses, who maintains the rules, and the reads the owner confirmed free of side
  effects; the system owner signed it before the workstation can be leased.

## Logons the bastion cannot carry (decision 0024)
- [ ] Serial consoles go through a console server with SSH per port (an ordinary SSH target); each device's console has
  an idle timeout and auto-logout. A jump target with a cable is used only where no console server fits, the reason
  recorded, and the cable declared as a path (see the non-IP paths above).
- [ ] Old-TLS consoles: the firmware update to TLS 1.2 or later was tried first; otherwise a re-terminator on a plant
  host in the zone sits behind a Warpgate HTTPS target. RDP with an old browser is for Java applet and KVM consoles only.
- [ ] Each jump target (pattern P-F) is plant-owned, in exactly one zone, never dual-homed, runs no other workload and
  holds only the old clients its systems need; its patching and hardening owner is named.
- [ ] Its conduit (systems and ports) and the plaintext leg to each device are recorded and signed by the system owner;
  its old browser runs in kiosk mode on an allowlist of those consoles, with no internet and no mail.
- [ ] No port, agent or X11 forwarding and no sftp or scp on its SSH service and in the Warpgate role; no RDP clipboard,
  drive, printer or USB redirection; BMC virtual media off or declared; no writable image store.
- [ ] It is rebuilt from a signed image on a schedule (fresh per session where possible); at lease end the session's
  processes are ended. It stands in a locked cabinet with its USB ports disabled.
- [ ] Until the account mapping is established in the lab: one session at a time per jump target, or one target entry
  per person.
- [ ] Each old system's shared credential: rotated by its owner after each lease, or held under break-glass escrow, or
  recorded as a residual with who knows it and how often it changes; never in a file on the jump target.

## Accounts and secrets
- [ ] The system binds to the edge's facade; people keep their account names (P-B, P-D).
- [ ] Service accounts the system uses are workloads with an owner, rotated on a schedule (0003).
- [ ] One legacy-native break-glass account per system, its value escrowed under dual control; a break-glass drill was
  run and the account rotated afterwards (0008).
- [ ] Every person who will receive lease credentials registered a hardware key with PRF support (0009); people without
  one are told P-B and P-D are not available to them.
- [ ] The edge's officer key holder is named and is not a core administrator (0007); the edge's ceiling is signed.
- [ ] The ceiling's classes include every class the edge's targets need: a target carried by a privileged group needs
  `privileged`, or KeyClerk drops each of its leases ("a lease class the ceiling does not allow", shown only in the
  desk's edge state, `last_dropped`; full-stack runs 6 to 8).

## Evidence and time
- [ ] The organisation's evidence store is reachable from the edge; the recording store size and its free-disk floor
  are set and the owner knows when offline sessions stop (0009).
- [ ] The edge has a time source while online (NTS where possible) and, on an assured edge, a TPM (0007).

## Local access (decision 0009)
- [ ] The dedicated access port is labelled, inside the locked cabinet, and its link-up window tested (SSH only).
- [ ] No Wi-Fi on the edge, or its purpose recorded.

## Updates (decision 0009)
- [ ] The edge pins the update-signing public key; the first update was pulled through the core's mirror.

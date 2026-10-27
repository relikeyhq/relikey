# 0024: Logons the bastion cannot carry: console servers, a legacy client jump target, no protocol code in ReliKey

- Status: accepted (operator, decide loop 2026-10-25), draft 2 after prior art, a conformance review and a red team
  (a review record kept with the maintainer, amendments 1 to 13). The two lab facts (point 7, the SSH recording's input)
  are settled in full-stack run 3; the interim rules hold until then.
- Date: 2026-10-25
- Changes: nothing in 0002 (the bastion stays the only path in). Adds access pattern P-F.
- Builds on: 0002, 0008 (thick clients on a jump host behind RDP), 0009 point 4, 0019 (P-E), 0020

## Context
The patterns cover most legacy logons: SSH, RDP, VNC, database consoles and web UIs (P-A, including web UIs on plain
HTTP, where the person's leg is TLS and the last hop inside the zone is plaintext), proxy-trusting web apps (P-C), LDAP
binds (P-B, P-D), OT protocols and vendor suites (P-E), and Kerberos (0014 part B). Two gaps remain:
- **Telnet, rlogin and serial consoles.** Warpgate has no telnet target, and a serial console is not a network service.
- **Old TLS.** Warpgate's HTTPS target uses rustls, which speaks TLS 1.2 and later only, so it cannot reach a web UI on
  TLS 1.0 or 1.1, SSLv3 or export ciphers. The common case is an old management console: a server's or a switch's
  out-of-band controller, often with a Java applet console.

0019 and 0020 settled the shape: ReliKey writes no protocol parser and carries no network reach into the zone; the
work happens on a plant host inside the zone, reached through the bastion and recorded. The prior art agrees: a
privileged-access product reaches such clients from a hardened host inside the network (CyberArk's connection
components, BeyondTrust's Jumpoint), and serial gear is reached through a console server with SSH per port.

## Decision
1. **Serial: a console server first.** Where a serial console is needed, a console server inside the zone offers each
   port over SSH, and Warpgate reaches it as an ordinary SSH target (P-A): no jump host. The device's console has an
   idle timeout and auto-logout set, so a console left logged in does not outlive the lease. A jump target with a cable
   is the fallback, with the reason recorded (amendments 1, 10).
2. **Old TLS: an update first, then a re-terminator, then the jump target.** First the console's firmware is brought
   to TLS 1.2 or later where the vendor allows. Otherwise a TLS re-terminator on a plant host inside the zone speaks
   the old TLS to the console and offers TLS 1.2 or later to a Warpgate HTTPS target, so the session keeps HTTP-level
   records and the weak TLS stays off the edge. RDP to the jump target with an old browser is for Java applet and KVM
   consoles only (amendment 2).
3. **Pattern P-F, the legacy client jump target, for what is left:** telnet and rlogin, Java and KVM consoles, and
   serial where no console server fits. A hardened plant host inside the system's zone holds only the old clients;
   it is a target like any other, reached only through Warpgate on a lease, privileged by default, with KeyClerk's
   session-start approval as for P-E. Telnet, rlogin and serial run over SSH to it (text recording); Java and KVM
   consoles over RDP (video).
4. **One zone, a declared conduit.** Each jump target sits in exactly one zone and is never dual-homed. Its conduit
   lists the systems and ports it reaches, signed by the system owner; the zone-internal leg from it to the device
   (telnet, old TLS, a serial cable as a physical path) is recorded as owner-declared plaintext. The exposure test
   confirms nothing outside the zone reaches the jump target except the bastion (amendments 8, 12).
5. **No side channels.** On the jump target's SSH service and in the Warpgate role: no port forwarding (local, remote
   or dynamic), no agent or X11 forwarding, no sftp or scp. In its RDP: no clipboard, drive, printer or USB
   redirection. A BMC console's virtual media is off or declared, and the jump target holds no writable image store.
   File transfer is a separate, declared and recorded mechanism, or none. Otherwise P-F would rebuild the network reach
   0019 rejected (amendments 3, 4, 11).
6. **Contained, rebuilt, single-purpose.** The jump target runs no other workload; its old browser runs in kiosk mode,
   allowed only the declared consoles' addresses and Java exceptions, with no internet and no mail. It is rebuilt from
   a signed image on a schedule, preferably fresh for every session; at lease end every process of that session is
   ended (no terminal multiplexer, scheduled job or service left behind). It stands in a locked cabinet with its USB
   ports disabled (amendments 6, 8, 10).
7. **Who the person is on the jump target is a fact to establish.** Warpgate signs in to an SSH target as one
   configured account (`targets.py`: one username per target), so concurrent people share it. Until the next lab run
   establishes how Warpgate maps a person to the target's account for SSH and RDP: one session at a time per jump
   target, or one target entry per person (amendment 5).
8. **The old system's shared credential.** Most telnet and serial gear cannot bind to LDAP, so P-B rarely applies. By
   default the owner rotates the credential after each lease, or holds it under break-glass escrow; otherwise it is a
   named residual: who knows it and how often it changes (NERC CIP-007 R5 asks the same). It is never in a file on the
   jump target (amendment 7).
9. **ReliKey writes no protocol code for it.** No telnet target and no TLS shim on the edge: the edge holds the bundle
   verifier, the leases and the bastion's admin token, and deliberately weak TLS does not belong there. A telnet target
   in Warpgate is a possible upstream contribution (it would cover telnet, not old TLS), filed only on the operator's
   go.

## Consequences
- The gaps close with no new code in ReliKey: patterns, checklist items and plant hosts the owner already knows how to
  run (console servers, a re-terminator, a jump target).
- Framework reading, stated: in NERC CIP-005 terms the Intermediate System is the edge (the bastion), where MFA and
  encryption end; the jump target is an in-zone tool host, not an Intermediate System. NIST SP 800-82r3 shows jump hosts
  mainly in a DMZ; here the edge plays that role, as for P-E. IEC 62443-3-3 SR 5.1 and 5.2 hold with point 4, SR 1.3
  holds at the bastion with point 8 as the compensating countermeasure at the device, and SR 2.8 is met in part: video
  is not event-level, which point 2 narrows.
- Evidence states what it holds. Whether Warpgate's SSH recording keeps input as well as output is a fact to establish
  in the next lab run: keystrokes that are not echoed are invisible in an output-only record, and echoed passwords can
  land in recordings, so access to recordings stays restricted (amendment 9).
- Old SSH (ssh-dss host keys, group1 key exchange, SHA-1 signatures) is probably carried by P-A, since Warpgate's SSH
  client list goes down to DH_G1_SHA1; whether it accepts ssh-dss host keys is established in the same lab run. Until
  then, an SSH target Warpgate refuses goes through P-F.
- The jump target is one more plant host to keep up, and its old clients are weak by nature; points 4 to 6 bound what
  a compromise of it reaches and how long it lasts.

## Consider the opposite
Guacamole carries telnet natively, with a text typescript and a graphical recording: a better record than SSH to a
jump host. Against it: it would be a second gateway beside Warpgate, against 0002. A TLS shim on the edge gives HTTP
records too, but puts weak TLS on the most sensitive box; point 2's re-terminator gets the records without that.

## Changelog
- 2026-10-25: accepted (operator).
- 2026-10-25: draft 2 after the review (amendments 1 to 13): console servers first for serial; firmware update, then
  a re-terminator in the zone, before RDP for old TLS; one zone and a declared plaintext leg; no SSH or RDP side
  channels; kiosk, rebuild and process cleanup; the account mapping and the SSH recording's input as lab facts; a
  realistic route for shared device credentials; the framework reading stated.
- 2026-10-25: proposed (decide loop on the logons the bastion cannot carry).

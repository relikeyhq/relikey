# 0019: Protocols the bastion cannot carry: through a plant engineering workstation, not network reach

- Status: accepted (operator, 2026-10-24), draft 2 after the red team (operator: "red team, prior art, attack from 5
  different angles, then build back up with blue team"). Pattern P-E is in model/patterns.yaml and the installation
  checklist; the protocol mediator (point 6) is not decided.
- Date: 2026-10-24
- Changes: nothing in 0002 (the bastion stays the only path in). Adds access pattern P-E. 0007 point 6 (remote reach
  as an optional plugin carrying bastion sessions only) is unchanged.
- Builds on: 0002, 0007, 0009, 0013, KeyClerk 0023 (session constraints, the capability declaration, S5 session-start
  approval, S8 at the gate vs corrected after)
- Red team: five angles on draft 1 (network, identity and control plane, OT process safety, edge host and supply
  chain, governance and evidence); the record is kept with the maintainer.

## Context
Warpgate carries SSH, HTTPS, Kubernetes, MySQL, PostgreSQL, RDP and VNC. Much OT work needs something else: Modbus/TCP,
EtherNet/IP and CIP, S7comm, OPC-DA over DCOM, PROFINET tooling, and vendor engineering suites (Siemens TIA Portal,
Rockwell Studio 5000, Schneider EcoStruxure) that talk their own protocols to a controller. Today an engineer has to
be on the plant network, or a vendor installs its own remote access beside ReliKey: the back door 0009 and the
installation checklist try to remove.

Draft 1 proposed lease-gated network reach from the remote person's device into the plant, carried by a NetBird peer
on the edge. The red team rejected it. Every angle's worst finding traced to that one choice:
- **A second trust root.** A mesh control plane can grant reach that no KeyClerk signature or officer ceiling allowed,
  and can keep it after a lease ends offline.
- **Write and stop authority that no network rule can tell from a read.** It reaches everything behind the target
  (backplane routing, gateways, the safety system), from an endpoint nobody vouches for.
- **Enforcement outside the agent's process and trusted clock.** Firewall and mesh state that can fail open.
- **Flow logs in place of recordings.** It contradicts the product's own claim.

The prior art points the same way. NERC CIP-005-8 R2 allows interactive remote access to these systems only through an
Intermediate System, with multi-factor sign-in at it and the ability to disable active vendor remote access. CISA's
exposure-reduction guidance says to use a jump host for monitored access and never to connect directly to a PLC, HMI or
RTU. NIST SP 800-82r3 names a set period and a call from the OT site to the remote person as compensating controls.
The products that do offer network reach (Secomea agents, BeyondTrust's Network Tunnel Jump, Teleport TCP apps) scope it
per host and port but filter no protocol functions; several others (Claroty, Zscaler, Xona) market against broad network
access.

## Decision
1. **Pattern P-E, the engineering workstation.** Where a system can only be worked with a vendor suite or an OT protocol,
   the tool runs on a plant-owned engineering workstation inside the system's zone. A person off site reaches that
   workstation only through the bastion: RDP through Warpgate, on a lease, passkey sign-in, recorded. The workstation's
   own path to the controller is the plant's existing conduit, inside the zone; ReliKey adds none.
2. **The workstation is a target like any other**, with its own entitlement and risk class. A lease for it is a lease for
   the work the tools on it can do, which is everything they can do to the controllers it reaches. Its risk class says so
   (privileged by default).
3. **Someone on site knows.** For a workstation that reaches controllers, the lease carries KeyClerk 0023's session-start
   approval, by a person at the site where the deployment has one, and the session is shown on the edge's local page.
   Where the plant runs lockout/tagout, the approval is its hook.
4. **The workstation's reach is declared, not assumed.** Installation records which controllers and safety systems the
   workstation can reach (the conduit), and the system owner signs that record. A workstation that reaches a safety
   instrumented system is a separate entitlement, never bundled with ordinary controller work.
5. **No raw network reach in ReliKey.** ReliKey does not route, bridge, or carry L3 or L2 reach from a remote device into
   a zone, whether on a lease or otherwise, with NetBird or any other carrier. Remote reach (0007 point 6) still carries
   bastion user sessions only.
6. **Later, its own decision: a protocol mediator.** For read-only diagnostics on protocols whose functions can be
   parsed (Modbus/TCP function codes, OPC UA reads), an edge-side proxy could allow only read functions per lease and
   log every request: a control at the gate with content evidence. It needs its own prior art and red team.

## How P-E answers the red team
| Finding (red team record) | P-E |
|---|---|
| Second trust root; a mesh grants or keeps reach (I1-I3, H3) | answered: no mesh authority; Warpgate roles come only from signed leases, as today |
| Routing, L2 bridging, spoofing, secondary ports, the edge reachable (N1, N3-N6, N8, N9, I9) | answered: no reach is carried; only RDP to one host through the bastion |
| Rules fail open, boot order, privileges, footprint (H1, H2, H5, H7) | answered: no new edge component; the agent's existing lease enforcement applies |
| Reach outlives the lease (N7, H3) | answered: the RDP session ends with the lease, through the existing session closing |
| Infected remote laptop, device not person (S7, N6, I4, I5) | answered: the tools run on a plant-owned workstation; the remote device carries only a recorded RDP session |
| Flow logs as evidence, intent against action (S5, G2, G6, G7) | answered for the session: full video recording of the workstation; residual for the controller (below) |
| Operator unaware, concurrent changes (S8, S9) | partly: session-start approval and the local page (points 3); concurrency is KeyClerk 0023 concurrency on the workstation target |
| Reads and writes alike, STOP, download (S1-S3, G5) | residual: the workstation can do what its tools can; bounded by risk class, approval and recording, not by protocol |
| Pivot through the target, safety system (N2, S4) | residual made explicit: the workstation's conduit is declared and owner-signed; a safety system is its own entitlement |
| Lease end mid-download (S10) | partly: the end is announced in the session first (KeyClerk 0023 windows end with a warning); the RDP cut leaves the workstation, not the controller, mid-operation |
| Standards (S11, G4) | answered: an intermediate system (NERC CIP-005), mediated and recorded (NIST 800-82, IEC 62443), with the owner's recorded consent to the conduit; CIP-005's ability to disable active vendor access is the lease's revocation and the edge closing the session; NIST's call from the site is the session-start approval |
| Normalisation, public claim, scope (G1, G3, G11) | answered: no weaker control is introduced; "the only path in is the wrapper" stays true |

## Consequences
- The plant needs an engineering workstation per zone with the vendor suites licensed on it, patched and owned by the
  plant. Many plants already have one; ReliKey makes it reachable safely rather than adding a tunnel.
- A vendor whose tool must run on its own laptop cannot use ReliKey for that work. That is the intended limit, stated to
  the customer, not a gap to close quietly.
- Model: pattern P-E is in model/patterns.yaml (no new flows: RDP to a host in the legacy zone through the bastion is
  pattern P-A's path).

## Residuals
- Inside the session the workstation's tools can change controllers in any way they can; the recording shows what was
  done, the lease and approval bound who and when. A protocol mediator (point 6) is the only way to bound what, and only
  for parseable protocols.
- A compromised workstation is a compromised engineering station; patching and hardening it is the plant's, and the
  installation checklist names it.
- The session-start approval fails closed when nobody can approve, which is the cost the operator accepted with KeyClerk
  0023 S5.

## Rejected (draft 1)
Raw lease-gated network reach from a remote device, with any carrier. If it is ever wanted, it is a different product
consuming KeyClerk leases, carrying the red team's properties as requirements, and never under ReliKey's evidence claim.

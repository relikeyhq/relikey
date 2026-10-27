# 0020: Read-only diagnostics: a diagnostic workstation on a read-only conduit, not a mediator in ReliKey

- Status: accepted (operator, 2026-10-24), draft 2 after the red team (operator, 2026-10-24: "GO" on 0019's open
  point 6, with prior art and a red team first). The diagnostic workstation is a P-E variant in model/patterns.yaml and
  the installation checklist.
- Date: 2026-10-24
- Builds on: 0001 (a distribution, not an engine), 0002, 0019 (pattern P-E; this answers its point 6), KeyClerk 0023
- Red team: five angles on draft 1 (parser and protocol semantics, plant safety of reads, architecture and trust,
  evidence and governance, edge implementation) and a prior-art scan; the record is kept with the maintainer.

## Context
0019 meets OT engineering work with pattern P-E: a plant-owned engineering workstation reached through the bastion and
recorded; inside the session the tools can do whatever they can to a controller. Much remote work is only diagnostics.
0019 point 6 asked whether a mediator could bound WHAT is done for parseable protocols: forward only reads, log every
request.

Draft 1 put such a mediator on the edge. The red team rejected it: its worst findings all land on ReliKey owning a
protocol parser.
- **The riskiest code on the edge.** A differential between the mediator's parse and the controller's defeats the
  allowlist, and no conformance-tested pure-Go OPC UA stack exists.
- **Not truly read-only.** Read-only depends on the device and the address, not on the function code: some reads clear
  counters or acknowledge alarms.
- **Reads still load fragile controllers.** They take the connection slots the HMI needs and outlive a failure.
- **A second authority.** The mediator would be a second lease verifier and the only author of its own evidence.
- **The rejected reach again.** Placed anywhere but behind the bastion, it rebuilds 0019's rejected network reach.

The prior art shows that function-code filtering is commodity. Certified industrial firewalls (Tofino, Moxa, Fortinet,
Cisco, Palo Alto) allowlist functions per device and unit. Read-only data at rest is served by historians and replica
servers behind a DMZ or a unidirectional gateway (NIST SP 800-82r3).

## Decision
1. **ReliKey writes no industrial protocol parser.** It does not parse, filter or proxy Modbus, OPC UA or any other
   control protocol. A protocol filter is the plant's equipment, chosen and certified for it.
2. **The diagnostic workstation, a variant of P-E.** For diagnostics, the plant provides a workstation whose conduit to
   the controllers is made read-only by the plant's own control: an industrial firewall that allows only read functions
   for that workstation, per device, unit and address range, with its rate and connection limits; or a replica
   (historian or OPC UA server) fed one way, so the workstation never touches the controller. ReliKey gates and records
   the person's session on it exactly as for P-E: a lease, RDP through the bastion, recorded, session-start approval on
   site, the session on the local page.
3. **The read-only conduit is a declared, signed fact.** Installation records the workstation's conduit (which
   controllers, which enforcement device or replica, which functions and addresses, who maintains the rules) and the
   system owner signs it, with which reads the owner has confirmed free of side effects. ReliKey checks that the record
   exists before the target can be leased; it does not claim to enforce it.
4. **Separate entitlements, same discipline.** A diagnostic workstation is its own target and entitlement, distinct from
   an engineering workstation. "Diagnostic" lowers nothing: the same approval tier, bounded duration and owner consent as
   any lease. The lease carries its purpose and, for a vendor, a reference to the contract that covers the data.
5. **What the evidence says, and no more.** ReliKey's evidence for such a session states: who, on which lease, approved by
   whom, the recording, and that the workstation's conduit was declared read-only by the owner, enforced by the named
   device or replica. It never states that the controller was only read, or anything about the controller's state.
6. **Ongoing monitoring is not a lease.** Continuous read-only data (trends, alarms, dashboards) belongs in the plant's
   historian, DMZ server or diode, not in remote sessions; whether ReliKey has any role in modern telemetry from legacy
   systems is a separate question (operator, 2026-10-24, observability), to be decided on its own.

## How draft 2 answers the red team
| Findings | Draft 2 |
|---|---|
| Parser risk, differentials, OPC UA stack, isolation, footprint, tests (P1, E1-E3, E10) | answered: no parser in ReliKey |
| Second verifier, self-written evidence (A4, G2) | answered: the lease is enforced by the agent as for any target; the conduit is enforced by the plant's device, recorded as a signed declaration |
| Reach rebuilt, site-LAN listener, workstation bypass (A1-A3) | answered: no new listener; access is the bastion session; the read-only property is the conduit's own |
| Side effects, unit ids, subscriptions, load, slots, failures (P2-P4, S1-S6, E4-E9) | moved to where they can be enforced: the owner's rule set on a device built for it, with the owner's confirmation of side-effect-free reads; residual stays the owner's, stated |
| Claims, approval bar, personal data, confidentiality, vendors (G1, G3, G5-G7, S11) | answered: evidence scoped to declarations; no lower tier; purpose and contract reference on the lease; no per-request content log in ReliKey (the session recording and the firewall's own logs) |
| Site awareness, safety systems (S8, S9) | answered: session-start approval and the local page; a safety system's read-only interface is a separate entitlement, as in 0019 |
| Stale values become advice (S7) | residual: a human-factors risk of any remote diagnosis; the installation checklist names it |

## Consequences
- A plant that wants bounded remote diagnostics needs an industrial firewall rule set or a replica for the diagnostic
  workstation. Many already have one; ReliKey records it and gates the people.
- ReliKey's claim stays as strong as its mechanism: it proves who and when, and records what was shown; the plant's
  device proves what could pass.

## Rejected (draft 1)
A protocol mediator in ReliKey. If a customer has no read-only control at all and a mediator is wanted, it is a
separate product or a certified third-party device, built to the red team's properties, never ReliKey's edge parser.

# 0021: Legacy telemetry and certificates: recipes, an inventory and the edge's own certificates, not a relay or CLM

- Status: accepted (operator, 2026-10-24), draft 2 after the red team (operator, 2026-10-24: "couldn't ReliKey also
  act as an observability modernizer? ... take ALL old protocols into account and try to standardize on a select few NEW
  ones, try to be crypto agile, PQC. We could also try to tie in modern CLM/certificate renewal - fight me"). Not built:
  the inventory (point 3), the edge's ACME (point 4) and the recipes (point 2) are work items.
- Date: 2026-10-24
- Changes: nothing in 0002 (no new flows into or out of the legacy zone). Crypto agility and PQC move to 0022.
- Builds on: 0001, 0002, 0003, 0019, 0020
- Red team: five adversarial angles (protocols, crypto agility and PQC, certificate lifecycle for legacy, architecture
  and security, product fit) and a prior-art scan; the record is kept with the maintainer.

## Context
The systems ReliKey fronts report in old ways (SNMPv1/v2c, UDP syslog, NetFlow, IPMI, WMI, OT polling and event
protocols, scraped consoles, SMTP alerts), and hold certificates that expire unnoticed, are self-signed or use RSA-1024
and SHA-1. Draft 1 proposed that the edge convert all of it into a few modern protocols (OTLP, syslog over TLS, IPFIX),
be crypto agile and post-quantum, and run certificate lifecycle for the legacy devices behind it, including installing
certificates on them.

The red team found four different things bundled in one:
- **A relay on the edge** that inverts 0002 (polling in, listeners out), puts device credentials (often read-write
  SNMP communities, admin-level v3 and IPMI keys) and untrusted UDP listeners on the enforcement box, breaks the edge's
  footprint, and depends on receivers that are still alpha (SNMP, flows) or missing (traps, every OT protocol). "All
  old protocols" means writing receivers, which 0001 and 0020 rule out, and translation invents meaning that the
  sources never had.
- **Crypto agility and PQC** aimed at the wrong asset (telemetry), while the things that last stay classical: signed
  bundles and ceilings, the lease relay and the break-glass escrow. "Algorithms as configuration" would also invite
  downgrade.
- **Certificate installation on devices**: access by another name, with standing admin credentials, writes outside any
  lease or recording, per-vendor installers and keys escrowed on the edge.
- **A crypto and certificate inventory**: the one part that strengthens ReliKey's evidence without new reach.

## Decision
1. **No telemetry relay in ReliKey.** The edge does not poll, receive or convert telemetry from legacy systems, and
   holds no device monitoring credentials. 0002 stays as it is.
2. **Integration recipes instead.** VDHome publishes and supports tested OpenTelemetry Collector configurations for the
   mature conversions only (syslog RFC 3164/5424, read-only SNMP polling, flow records as OTLP logs) towards OTLP over
   TLS. They run on a host the organisation owns, never on the ReliKey edge, and follow the red team's provenance rules:
   - each record keeps its original payload, source time and receive time, the mapping version and its quality;
   - unknown stays unknown: no guessed year, unit or enum meaning;
   - loss and drop counters are exported as telemetry.
   OT telemetry stays in the plant's historian, OPC UA or Sparkplug stack. People who administer that collector host
   reach it through ReliKey like any other target.
3. **A read-only crypto and certificate inventory.** The edge records what it already observes and nothing more:
   - the SSH host keys and algorithms of targets (deploy/edge/targets.py pins them);
   - TLS certificates presented on the bastion's own target connections;
   - its own certificates and keys.
   It reports them to the core, and they are exported as a CycloneDX cryptography bill of materials in the evidence:
   expiry, key type and size, signature algorithm, and weak algorithms flagged (RSA-1024, SHA-1, DSA). Entries are
   marked as observed, never as verified, and no scan adds a flow. Where the inventory's records live is a question
   for KeyClerk (machine identity is its lane).
4. **The edge's own certificates only.** The edge and the core obtain their own TLS certificates from the customer's CA
   with ACME and ACME Renewal Information (RFC 9773): short-lived and renewed automatically. ReliKey runs no CA and no
   registration authority.
5. **Certificates on legacy devices are not ReliKey's to install.** A device's certificate is changed by a person in a
   leased, recorded session (P-A, or P-E for OT servers), in a change window with on-site approval, or by the customer's
   CLM product. The inventory (point 3) shows what is due. Machine-identity governance (which device gets which
   certificate, from which CA, approved by whom), if it is ever wanted, is KeyClerk's.
6. **Crypto agility and PQC are 0022**, ReliKey-wide, not part of this decision.

## Consequences
- ReliKey stays an access product, and gains evidence (the inventory) rather than a category. Telemetry work is
  integration services with no product liability for monitoring coverage.
- A customer who wants telemetry modernisation as a product is pointed to the OTel ecosystem or to CLM vendors. VDHome
  can deliver that through services.

## Rejected (draft 1)
A telemetry relay on the edge; "all old protocols"; IPFIX as a target (the Collector receives it and does not emit it);
the edge as a registration authority or installer of device certificates; crypto agility as telemetry configuration.

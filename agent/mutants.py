# SPDX-License-Identifier: EUPL-1.2
"""Mutation check for the verifier: remove one guard at a time, the tests must fail every time.

A guard whose removal leaves the tests green is untested. Equivalent mutants are left out with the reason:
- a key listed twice in a multi-signed object: the signer list then never equals the deduplicated required set, so
  it is refused by the next check either way; the explicit check stays for the reference's message.
- the pinned-key comparison in Unseal: the signature is verified with the pinned key right after, so a different key
  is refused either way; the comparison stays for the reference's message. Run from agent/:  python mutants.py
Each mutant names the file, the exact text and its replacement; the file is restored after every run.

    python mutants.py                   every mutant (main, the nightly run, before a release)
    python mutants.py --changed BASE    the mutants a change since BASE can affect (a pull request): those in a changed
                                        file or in a package whose tests or test data changed; a change to a shared
                                        test helper, this script, build.py or a go.mod/go.sum runs all of them
    python mutants.py --shard 2/4       the second of four deterministic parts of the list (CI runs them in parallel)
"""
import argparse
import os
import posixpath
import subprocess
import sys
from pathlib import Path

K = Path("internal/kcedge")
A = Path("internal/apply")
G = Path("internal/agent")
MUTANTS = [
    ("the ceiling policy is not run on the tick", G / "agent.go",
     "kcedge.LiveAt(*rec.Bundle, a.Pins, now, kcedge.CeilingPolicyGo)", "kcedge.LiveAt(*rec.Bundle, a.Pins, now, nil)"),
    ("the ceiling refuses no one", K / "ceiling.go",
     "\tif !inside {\n", "\tif false {\n"),
    ("two people may share a username", A / "apply.go",
     "if p, seen := person[l.Username]; seen && p != l.Person {", "if false {"),
    ("roles without a lease are kept", A / "apply.go",
     "if _, ok := du.Roles[role]; !ok && ou.Roles[role].Active {", "if false {"),
    ("users without a lease are kept", A / "apply.go",
     "add(Action{Kind: DeleteUser, Username: name, UserID: ou.ID, Why: \"no live lease\"})", ""),
    ("orphaned sessions stay open", A / "apply.go",
     "\tfor _, s := range o.Orphans {", "\tfor _, s := range o.Orphans[:0] {"),
    ("a session still signing in is closed as an orphan", A / "apply.go",
     "if s.AccountID == \"\" && s.Account == \"\" && len(s.Targets) == 0 {", "if false {"),
    ("an unmanaged account holding a governed role goes unreported", A / "governed.go",
     "if g.Active && governed[g.Role] &&", "if false && g.Active && governed[g.Role] &&"),
    ("an ungoverned role on an unmanaged account is reported", A / "governed.go",
     "if g.Active && governed[g.Role] &&", "if g.Active &&"),
    ("an expired grant on an unmanaged account is reported", A / "governed.go",
     "(now.IsZero() || g.Expires == nil || g.Expires.After(now))", "true"),
    ("a governed-roles file that is not a SCIM list reads as nothing governed", A / "governed.go",
     "if !slices.Contains(l.Schemas, scimList) {", "if false {"),
    ("a malformed governed_roles is read as absent", Path("internal/kcedge") / "bundle.go",
     "governed, why := governedRoles(obj)", "governed, why := governedRoles(obj)\n\twhy = \"\""),
    ("the clerk's signed governed roles are ignored", Path("internal/agent") / "agent.go",
     "if desired.Governed != nil {", "if false {"),
    ("a rogue-account finding is emitted on every tick", Path("internal/agent") / "emit.go",
     "if a.rogue[name] == current[name] {", "if false {"),
    ("an address the desk learns after the lease went live is never asked for again", Path("internal/agent") / "agent.go",
     "|| (f.ok && !f.has && time.Since(f.tried) >= noAddressRetry)", "|| (false && f.ok && !f.has && time.Since(f.tried) >= noAddressRetry)"),
    ("a transient read of the bastion is not asked again within the tick", Path("internal/agent") / "agent.go",
     "if err == nil || attempt >= readAttempts ||", "if true || err == nil || attempt >= readAttempts ||"),
    ("a permanent read failure is asked again", Path("internal/agent") / "agent.go",
     "|| !bastion.Transient(err) ||", "|| false ||"),
    ("a read is asked again past the tick", Path("internal/agent") / "agent.go",
     "|| time.Now().Add(wait).After(budget) {", "|| (false && time.Now().Add(wait).After(budget)) {"),
    ("the agent's changes are not emitted as events", Path("internal/agent") / "agent.go",
     "a.emitApplied(res.Applied)", "_ = res.Applied"),
    ("a held or changed long-poll answer waits the full interval", Path("internal/agent") / "agent.go",
     "(r.held >= max(heldMin, a.Wait/2) || changed)", "(false && changed)"),
    ("an immediate unchanged answer is polled again at once (a tight loop)", Path("internal/agent") / "agent.go",
     "(r.held >= max(heldMin, a.Wait/2) || changed)", "(true || changed)"),
    ("an unchecked tick resolves a finding", Path("internal/agent") / "emit.go",
     "return // no check ran this tick: the last reported state stands", "_ = 0 // no check ran this tick"),
    ("an unchecked account's finding is not carried forward", Path("internal/agent") / "emit.go",
     "(o.RoguePartial || o.RogueUnchecked[name])", "(false && o.RogueUnchecked[name])"),
    ("a replayed fleet report is accepted", Path("../fleet/internal/fleet") / "inventory.go",
     "if e.Last != nil && r.Seq <= e.Last.Seq {", "if false {"),
    ("a fleet report with a stray clock is accepted", Path("../fleet/internal/fleet") / "inventory.go",
     "if d := r.At.Sub(now); d > fleetproto.Skew || d < -fleetproto.Skew {", "if d := r.At.Sub(now); false && d > fleetproto.Skew {"),
    ("a fleet report's signature is not checked", Path("pkg/fleetproto") / "report.go",
     "if !ed25519.Verify(key, message(raw), sig) {", "if false && !ed25519.Verify(key, message(raw), sig) {"),
    ("a silent edge is never marked silent", Path("../fleet/internal/fleet") / "inventory.go",
     "if e.Last != nil && now.Sub(e.LastSeen) > inv.silence {", "if false {"),
    ("a fleet answer other than 204 counts as delivered", Path("pkg/fleetproto") / "client.go",
     "if resp.StatusCode != http.StatusNoContent {", "if false {"),
    ("the agent reports to the fleet on every tick", Path("internal/agent") / "agent.go",
     "if !a.fleetLast.IsZero() && time.Since(a.fleetLast) < a.Pull {", "if false {"),
    ("an unreadable user without a live lease is kept", Path("internal/apply") / "apply.go",
     "if d.Users[name] != nil || ou == nil {", "if true || d.Users[name] != nil || ou == nil {"),
    ("an ended lease keeps its role while a close fails", Path("internal/apply") / "apply.go",
     "if ou.Roles[role].Active {", "if false {"),
    ("the agent changes the bastion in shadow mode", Path("internal/agent") / "agent.go",
     "case a.Mode != Enforce:", "case false:"),
    ("the agent never restores the bastion's hardening", Path("internal/agent") / "agent.go",
     "if err := h.Harden(ctx); err != nil {", "if err := error(nil); err != nil {"),
    ("a lease's role may reach targets the lease does not name", Path("internal/apply") / "apply.go",
     "if len(extra) > 0 {", "if false && len(extra) > 0 {"),
    ("a lease without a target is applied", Path("internal/apply") / "apply.go",
     'if l.Username == "" || l.Role == "" || l.Target == "" {', 'if l.Username == "" || l.Role == "" {'),
    ("outside text may rearrange the edge page", Path("internal/agent") / "page.go",
     "return utf8.RuneError", "return r + 0*utf8.RuneError"),
    ("a fleet report's fields may hold any text", Path("pkg/fleetproto") / "report.go",
     "if err := r.Check(); err != nil {", "if err := r.Check(); false && err != nil {"),
    ("the fleet answers any Host (DNS rebinding)", Path("../fleet/internal/fleet") / "server.go",
     'if ip := net.ParseIP(strings.Trim(host, "[]")); !(host == "localhost" || (ip != nil && ip.IsLoopback())) {',
     'if ip := net.ParseIP(strings.Trim(host, "[]")); false && !(host == "localhost" || (ip != nil && ip.IsLoopback())) {'),
    ("one operator pushes out another's sessions", Path("../fleet/internal/page") / "page.go",
     "if mine >= maxPerPerson {", "if false && mine >= maxPerPerson {"),
    ("the fleet page takes an answer from another issuer", Path("../fleet/internal/page") / "page.go",
     'if iss := r.URL.Query().Get("iss"); iss != "" && iss != p.Cfg.Issuer {', "if false {"),
    ("a registry change without a device-bound signature is taken", Path("../fleet/internal/registry") / "registry.go", "case !bound:", "case false && !bound:"),
    ("an officer is removed without a majority", Path("../fleet/internal/registry") / "registry.go",
     "if _, kept := next.officer(o.ID); !kept && !majority {", "if _, kept := next.officer(o.ID); false && !kept && !majority {"),
    ("an added officer need not prove their passkey", Path("../fleet/internal/registry") / "registry.go", "if _, ok := added[o.ID]; !ok {", "if _, ok := added[o.ID]; false && !ok {"),
    ("an older registry can come back", Path("../fleet/internal/registry") / "registry.go", "case next.Version != cur.Version+1:", "case false:"),
    ("a registry change need not name its previous", Path("../fleet/internal/registry") / "registry.go", "case next.Previous != cur.Hash():", "case false:"),
    ("an anchor without every officer's proof is taken", Path("../fleet/internal/registry") / "registry.go", "if _, ok := signed[o.ID]; !ok {", "if _, ok := signed[o.ID]; false && !ok {"),
    ("a passkey signed for another relying party is taken", Path("../fleet/internal/registry") / "webauthn.go",
     "if subtle.ConstantTimeCompare(raw[:32], want[:]) != 1 {", "if false && subtle.ConstantTimeCompare(raw[:32], want[:]) != 1 {"),
    ("a passkey signed on another origin is taken", Path("../fleet/internal/registry") / "webauthn.go", "case cd.Origin != origin:", "case false:"),
    ("a passkey signature without user verification is taken", Path("../fleet/internal/registry") / "webauthn.go",
     "if a.flags&flagUP == 0 || a.flags&flagUV == 0 {", "if false {"),
    ("a passkey signature for another statement is taken", Path("../fleet/internal/registry") / "webauthn.go",
     "case subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(base64.RawURLEncoding.EncodeToString(challenge))) != 1:",
     "case false && subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(base64.RawURLEncoding.EncodeToString(challenge))) != 1:"),
    ("a presentation without the code's secret is taken", Path("../fleet/internal/enrol") / "enrol.go",
     "case p.Slot != s.ID || !hmac.Equal([]byte(hash(p.Secret)), []byte(s.SecretHash)):",
     "case false && (p.Slot != s.ID || !hmac.Equal([]byte(hash(p.Secret)), []byte(s.SecretHash))):"),
    ("a presented key need not prove possession", Path("../fleet/internal/enrol") / "enrol.go",
     "if !ed25519.Verify(key, presentMessage(fleet, s.ID, s.SecretHash), sig) {",
     "if false && !ed25519.Verify(key, presentMessage(fleet, s.ID, s.SecretHash), sig) {"),
    ("a second key replaces the first for a slot", Path("../fleet/internal/enrol") / "enrol.go", 'case s.Active || s.Key != "":', "case s.Active:"),
    ("a short typed fingerprint check is taken", Path("../fleet/internal/enrol") / "enrol.go", "case len(plain(it.Typed)) < MinTyped ||", "case len(plain(it.Typed)) < 1 ||"),
    ("an activation may name another key's fingerprint", Path("../fleet/internal/enrol") / "enrol.go", "case plain(it.Fingerprint) != plain(Fingerprint(s.Key)):", "case false:"),
    ("a relay is admitted without the approver reading its screen", Path("../fleet/internal/enrol") / "enrol.go",
     'case (s.Kind == Relay || s.Kind == Site) && (it.ReadBy != a.Approver || it.ReadHow != "on site"):', "case false:"),
    ("a batch may exceed ten slots", Path("../fleet/internal/enrol") / "enrol.go", "case len(a.Items) == 0 || len(a.Items) > MaxBatch:", "case len(a.Items) == 0:"),
    ("a slot is opened from another origin", Path("../fleet/internal/page") / "page.go",
     'return err == nil && r.Header.Get("Origin") == u.Scheme+"://"+u.Host', 'return err == nil || r.Header.Get("Origin") == u.Scheme+"://"+u.Host'),
    ("a slot is opened without a session", Path("../fleet/internal/page") / "page.go",
     "if !ok || p.Admin == nil || !p.sameOrigin(r) {", "if false && (!ok || p.Admin == nil || !p.sameOrigin(r)) {"),
    ("a second key for a slot is answered as taken in", Path("../fleet/internal/fleet") / "server.go",
     "case errors.Is(err, enrol.ErrTaken):", "case false && errors.Is(err, enrol.ErrTaken):"),
    ("an e-mail answer to another request is taken", Path("internal/kcedge") / "sealed.go",
     'if obj["nonce"] != nonce {', 'if false && obj["nonce"] != nonce {'),
    ("an e-mail answer for another lease is taken", Path("internal/kcedge") / "sealed.go",
     'if obj["lease_id"] != leaseID {', 'if false && obj["lease_id"] != leaseID {'),
    ("a 1.3 lease never gets its address", Path("internal/agent") / "agent.go",
     "l.leases = a.withEmails(ctx, l.leases)", "_ = l.leases"),
    ("the address is fetched on every tick", Path("internal/agent") / "agent.go",
     "if !seen || (!f.ok && time.Since(f.tried) >= 15*time.Second) ||", "if true ||"),
    ("the fleet page admits without the client role", Path("../fleet/internal/page") / "page.go",
     "case !slices.Contains(cl.Resource[p.Cfg.ClientID].Roles, p.Cfg.Role):", "case false && !slices.Contains(cl.Resource[p.Cfg.ClientID].Roles, p.Cfg.Role):"),
    ("the fleet page takes another sign-in's ID token", Path("../fleet/internal/page") / "page.go",
     "case cl.Nonce != pd.Nonce:", "case false:"),
    ("the fleet page takes a forged state", Path("../fleet/internal/page") / "page.go",
     'if r.URL.Query().Get("state") != pd.State {', "if false {"),
    ("the fleet page takes a stale sign-in", Path("../fleet/internal/page") / "page.go",
     "if !ok || p.Now().Sub(time.Unix(pd.At, 0)) > pendingTTL {", "if !ok {"),
    ("the fleet page takes any signed token as a logout", Path("../fleet/internal/page") / "page.go",
     "cl.Nonce != nil || cl.Events[logoutEvent] == nil ||", "cl.Nonce != nil ||"),
    ("a user is deleted although its session could not be closed", A / "apply.go",
     "if a.Kind == DeleteUser && closeFailed[a.Username] {", "if false {"),
    ("grants start after the shutdown signal", A / "apply.go",
     "if a.Kind.Grant() && ctx.Err() != nil {", "if false {"),
    ("sessions may run past their cap", A / "apply.go",
     "allowed > 0 && !d.Now.IsZero() &&", "allowed > 0 && false &&"),
    ("unmanaged users are planned for", A / "apply.go",
     "\t\tif o.Unmanaged[name] {\n\t\t\tp.Drift", "\t\tif false {\n\t\t\tp.Drift"),
    ("a session on a target no live role reaches stays open", A / "apply.go",
     "if !slices.ContainsFunc(o.TargetRoles[ts.TargetID], func(r string) bool { _, ok := du.Roles[r]; return ok }) {",
     "if false {"),
    ("signed bytes need not be canonical", K / "sealed.go",
     "v, err := CheckCanonical(raw)", "v, err := Parse(raw)"),
    ("the outer key id is not compared", K / "sealed.go",
     " || s.KeyID != KeyID(pinnedHex)", ""),
    ("the format inside is not checked", K / "sealed.go",
     'obj["format"] != format || ', ""),
    ("the key id inside is not checked", K / "sealed.go",
     ' || obj["key_id"] != KeyID(pinnedHex)', ""),
    ("another edge's bundle accepted", K / "bundle.go",
     "if o.b.Edge != pins.Edge {\n\t\terrs", "if false {\n\t\terrs"),
    ("an old serial accepted", K / "bundle.go",
     "if *o.b.Serial <= state.Serial {", "if false {"),
    ("issued in the future accepted", K / "bundle.go",
     "if o.issued.After(now.Add(Skew)) {", "if false {"),
    ("the clock may go back", K / "bundle.go",
     "if now.Before(newest.Add(-Skew)) {", "if false {"),
    ("an issue time before the newest accepted", K / "bundle.go",
     "if o.issued.Before(newest.Add(-Skew)) {", "if false {"),
    ("module hashes and release not checked", K / "bundle.go",
     "errs = append(errs, checkPolicy(o.b.Policy, pins)...)", "_ = checkPolicy"),
    ("leases without a ceiling accepted", K / "bundle.go",
     "if len(*o.b.Leases) > 0 || len(*o.b.VisitLeases) > 0 {", "if false {"),
    ("the held ceiling may disappear", K / "bundle.go",
     "if floor != 0 {", "if false {"),
    ("the ceiling does not narrow offline validity", K / "bundle.go",
     "min(classHorizon, offlineCap)", "min(classHorizon, offlineCap+1000000)"),
    ("revoked leases stay live", K / "bundle.go",
     "age <= time.Duration(horizon)*time.Hour &&\n\t\t\t!slices.Contains(*b.Revoked, x.LeaseID)",
     "age <= time.Duration(horizon)*time.Hour"),
    ("revoked visit leases stay live", K / "bundle.go",
     "now.Before(until) && !slices.Contains(*b.Revoked, x.LeaseID) {\n\t\t\tx.Ends = until\n\t\t\tout.VisitLeases",
     "now.Before(until) {\n\t\t\tx.Ends = until\n\t\t\tout.VisitLeases"),
    ("leases live before their start", K / "bundle.go",
     "if !from.After(now) && now.Before(until) && age", "if now.Before(until) && age"),
    ("the ceiling key set is not checked", K / "bundle.go",
     "\tif !sameKeys(c, ceilingKeys) {\n\t\treturn []string{\"a ceiling has exactly \"", "\tif false {\n\t\treturn []string{\"a ceiling has exactly \""),
    ("the ceiling signature is not checked", K / "bundle.go",
     "c, _, err := UnsealValue(sealed, officerHex, CeilingFormat)", "c, _, err := Object(nil), []byte(nil), error(nil); if o, ok := sealed.(Object); ok { if b, e := rawBytes(o[\"bytes\"].(string)); e == nil { c, _ = parseSigned(b) } }"),
    # KeyClerk 0.23.0 (amendment 0014d, AG-18, modules by hash)
    ("a sealed object may carry extra members", K / "sealed.go",
     'if !ok || !sameKeys(o, []string{"bytes", "key", "key_id", "signature"}) {', "if !ok {"),
    ("non-canonical base64 accepted", K / "sealed.go",
     "if err != nil || base64.StdEncoding.EncodeToString(raw) != b64 {", "if err != nil {"),
    ("an ended notice for other enrolment keys is acted on", K / "sealed.go",
     "if !slices.Contains(keys, Value(KeyID(ownEnrolmentKey))) {", "if keys != nil && false {"),
    ("an ended notice for another edge is acted on", K / "sealed.go",
     '\tif obj["edge"] != pins.Edge {\n\t\terrs = append(errs, "an ended notice for another edge")', '\tif false {\n\t\terrs = append(errs, "an ended notice for another edge")'),
    ("a statement may lack a required signer", K / "sealed.go",
     "if !slices.Equal(slices.Sorted(slices.Values(keys)), need) {", "if len(keys) == 0 {"),
    ("a statement signature is not verified", K / "sealed.go",
     "if err != nil || !verifyHex(key, raw, s.Signature) {\n\t\t\treturn nil, fmt.Errorf(\"the signature of key", "if _ = key; err != nil {\n\t\t\treturn nil, fmt.Errorf(\"the signature of key"),
    ("a policy module may carry bytes beside its hash", K / "bundle.go",
     "if len(mods[name]) != 1 || !ok || !hex64.MatchString(sum) {", "if !ok && sum != \"\" {"),
    ("fetched module bytes are not checked against the hash", K / "bundle.go",
     "if hex.EncodeToString(sum[:]) != expectedSHA256 {", "if hex.EncodeToString(sum[:]) == \"\" {"),
    ("an unlock field may hold a separator", K / "unlock.go",
     'if f == "" || strings.ContainsAny(f, "|\\r\\n") {', 'if f == "" {'),
    ("the ceiling may name another edge", K / "bundle.go",
     'if c["edge"] != edgeID {', "if false {"),
    ("an older ceiling accepted", K / "bundle.go",
     "} else if serial < floor {", "} else if false {"),
    ("ports are not checked", K / "bundle.go",
     "if n, isInt := asInt(p); !isInt || n < 1 || n > 65535 {", "if n, isInt := asInt(p); false && (!isInt || n < 1 || n > 65535) {"),
    ("classes are not checked", K / "bundle.go",
     "if !slices.Contains(classes, v.(string)) {", "if false && !slices.Contains(classes, v.(string)) {"),
    ("the newest time does not rise", K / "bundle.go",
     "if newest.IsZero() || o.issued.After(newest) {", "if newest.IsZero() {"),
    ("strings escape like RFC 8785 (no short forms)", K / "canon.go",
     "\t\tcase '\\b':\n\t\t\tb.WriteString(`\\b`)\n", ""),
    ("names in byte order reversed", K / "canon.go",
     "slices.Sort(names)", "slices.Sort(names); slices.Reverse(names)"),
    ("-0 accepted", K / "canon.go", ' || s == "-0"', ""),
    ("integers beyond 2^53-1 accepted", K / "sealed.go", "n < 0 || n > maxSafe", "n < 0"),
    ("negative integers accepted", K / "sealed.go", "n < 0 || n > maxSafe", "n > maxSafe"),
    ("a class without a horizon is live", K / "bundle.go",
     "classHorizon, ok := (*b.Horizons)[x.Class]", "classHorizon, ok := (*b.Horizons)[x.Class], true"),
    ("loose times accepted", K / "bundle.go",
     "if !isoTime.MatchString(s) {\n\t\treturn time.Time{}", "if false {\n\t\treturn time.Time{}"),
    # W2: officer passkeys and the anchor ceremony (decision 0026 points 16, 21, 30)
    ("a registration's client data is not checked", Path('../fleet/internal/registry') / 'webauthn.go',
     'if err := checkClientData(clientDataJSON, "webauthn.create", challenge, rp.Origin); err != nil {', 'if err := checkClientData(clientDataJSON, "webauthn.create", challenge, rp.Origin); false && err != nil {'),
    ('a registration without a credential is taken', Path('../fleet/internal/registry') / 'webauthn.go',
     'case a.flags&flagAT == 0 || a.coseKey == nil:', 'case false:'),
    ('a credential id of any length is taken', Path('../fleet/internal/registry') / 'webauthn.go',
     'case len(a.credID) < 16 || len(a.credID) > MaxCredentialID:', 'case false:'),
    ('backed up but not backup eligible is taken', Path('../fleet/internal/registry') / 'webauthn.go',
     'case a.flags&flagBS != 0 && a.flags&flagBE == 0:', 'case false:'),
    ('a registered key of any kind is taken', Path('../fleet/internal/registry') / 'webauthn.go',
     'if _, err := parseCOSE(a.coseKey); err != nil {', 'if _, err := parseCOSE(a.coseKey); false && err != nil {'),
    ('a synced passkey counts as device-bound', Path('../fleet/internal/registry') / 'webauthn.go',
     'DeviceBound: a.flags&flagBE == 0}', 'DeviceBound: true}'),
    ('a passkey is registered after the anchor', Path('../fleet/internal/admin') / 'admin.go',
     '\tif len(s.d.Versions) > 0 {\n\t\treturn errAnchored\n\t}\n\tfor id, c := range s.d.Candidates {', '\tif false {\n\t\treturn errAnchored\n\t}\n\tfor id, c := range s.d.Candidates {'),
    ('one passkey serves two officers', Path('../fleet/internal/admin') / 'admin.go',
     'if id != o.ID && c.CredentialID == o.CredentialID {', 'if false && id != o.ID && c.CredentialID == o.CredentialID {'),
    ('registering again keeps the signed draft', Path('../fleet/internal/admin') / 'admin.go',
     '\tif s.d.Draft != nil {\n\t\ts.d.Draft = nil\n', '\tif false && s.d.Draft != nil {\n\t\ts.d.Draft = nil\n'),
    ('the anchor is drafted before every named officer registered', Path('../fleet/internal/admin') / 'admin.go',
     'return registry.Change{}, false, nil // someone has not registered yet', 'continue'),
    ('the draft changes while it can be signed', Path('../fleet/internal/admin') / 'admin.go',
     'if s.d.Draft != nil && now.Before(s.d.Draft.Statement.Expires) {', 'if false && s.d.Draft != nil && now.Before(s.d.Draft.Statement.Expires) {'),
    ('an expired draft can be signed', Path('../fleet/internal/admin') / 'admin.go',
     'if d == nil || !now.Before(d.Statement.Expires) {', 'if d == nil {'),
    ('an anchor signature is not verified when given', Path('../fleet/internal/admin') / 'admin.go',
     'if _, err := rp.Verify(sig, d.Registry.Officers[i], d.Statement, now); err != nil {', 'if _, err := rp.Verify(sig, d.Registry.Officers[i], d.Statement, now); false && err != nil {'),
    ('an officer signing the anchor twice counts twice', Path('../fleet/internal/admin') / 'admin.go',
     '\td.Signatures = slices.DeleteFunc(d.Signatures, func(x registry.Signature) bool { return x.Officer == sig.Officer })\n', ''),
    ('an operator not named begins a registration', Path('../fleet/internal/page') / 'officers.go',
     '\tif !p.named(s.name) {\n\t\tfail(w, http.StatusForbidden, "you are not named as a first officer: the installer names them in fleet.json (officers)")\n\t\treturn\n\t}\n\tch :=', '\tif false {\n\t\tfail(w, http.StatusForbidden, "you are not named as a first officer: the installer names them in fleet.json (officers)")\n\t\treturn\n\t}\n\tch :='),
    ('a registration challenge is used twice', Path('../fleet/internal/page') / 'officers.go',
     '\tdelete(p.challenges, p.sessionID(r)) // one use, whatever the outcome\n', ''),
    ('a registration challenge never expires', Path('../fleet/internal/page') / 'officers.go',
     'if !had || !p.Now().Before(ch.until) {', 'if !had {'),
    ('a passkey step takes a form', Path('../fleet/internal/page') / 'officers.go',
     'case ct != "application/json":', 'case false && ct != "application/json":'),
    ('a passkey step comes from another origin', Path('../fleet/internal/page') / 'officers.go',
     'case !ok || p.Admin == nil || !p.sameOrigin(r):', 'case !ok || p.Admin == nil:'),
    ('a passkey step runs after the anchor', Path('../fleet/internal/page') / 'officers.go',
     'case p.Admin.Anchor() != "":', 'case false:'),
    ('a passkey step takes unknown fields', Path('../fleet/internal/page') / 'officers.go',
     '\tdec.DisallowUnknownFields()\n', ''),
    ('an operator not named is offered the passkey steps', Path('../fleet/internal/page') / 'officers.go',
     'MeNamed: p.named(s.name)', 'MeNamed: true'),
    ("the page's policy allows any inline script", Path('../fleet/internal/page') / 'page.go',
     'script-src \'"+scriptHash+"\'; ', "script-src 'unsafe-inline'; "),
    ("a second account under an officer's name registers", Path('../fleet/internal/admin') / 'admin.go',
     'if id != o.ID && c.Name == o.Name {', 'if false && id != o.ID && c.Name == o.Name {'),
    ("a passkey under your name from another account goes unflagged", Path('../fleet/internal/page') / 'officers.go',
     'if name == s.name && ok && o.ID != s.sub {', 'if false && name == s.name && ok && o.ID != s.sub {'),
]


# Which mutants a change can affect (--changed). A mutant is judged only by the tests of its own package (main() runs
# `go test ./<package>/`), so a weakened test or test data reaches only the mutants of that package. Shared test code
# reaches every package: a change to any of these runs every mutant. Paths are relative to the repository.
HARNESS_DIRS = ("agent/internal/fakes/", "agent/internal/testemit/", "fleet/internal/registry/regtest/")
HARNESS_FILES = ("agent/mutants.py", "agent/build.py")
# Files a package's tests read from outside the package (tests/test_mutants.py finds every "..": keep this complete).
TEST_INPUTS = {
    "agent/internal/agent": ("brand/mark/geometry.json",),   # page_test.go: the mark's geometry
    "agent/internal/apply": ("agent/internal/agent/",),       # seam_test.go: the agent package's imports
}


def repo_path(path: Path) -> str:
    """The mutated file relative to the repository root, as git names it (the mutant paths are relative to agent/)."""
    return posixpath.normpath("agent/" + path.as_posix())


def shared(f: str) -> bool:
    """Whether a changed file (repository-relative) is test code or build input shared by every package."""
    return f.startswith(HARNESS_DIRS) or f in HARNESS_FILES or posixpath.basename(f) in ("go.mod", "go.sum")


def tested_packages(f: str) -> set[str]:
    """The packages whose tests a changed file is part of: its own for a _test.go or test data, and any package that
    reads it from outside (TEST_INPUTS)."""
    pkgs = {p for p, inputs in TEST_INPUTS.items() if any(f == i or (i.endswith("/") and f.startswith(i))
                                                          for i in inputs)}
    if f.endswith("_test.go"):
        pkgs.add(posixpath.dirname(f))
    elif "/testdata/" in "/" + f:
        pkgs.add(("/" + f).split("/testdata/")[0].lstrip("/"))
    return pkgs


def select_changed(mutants: list, changed: list[str]) -> tuple[list, str]:
    """The mutants a change can affect, and why: all of them (shared test code changed), those in a changed file or in
    a package whose tests changed, or none."""
    harness = sorted(f for f in changed if shared(f))
    if harness:
        more = f" and {len(harness) - 1} more" if len(harness) > 1 else ""
        return list(mutants), f"shared test code or the harness changed ({harness[0]}{more}): every mutant"
    files = set(changed)
    pkgs = set().union(*(tested_packages(f) for f in changed))
    picked = [m for m in mutants if repo_path(m[1]) in files or posixpath.dirname(repo_path(m[1])) in pkgs]
    if not picked:
        return [], "no mutated file and no test of a mutated package changed: no mutant to run"
    mutated = {repo_path(m[1]) for m in picked} & files
    tested = {posixpath.dirname(repo_path(m[1])) for m in picked} & pkgs
    return picked, f"{len(mutated)} mutated file(s) and the tests of {len(tested)} package(s) changed"


def parse_shard(spec: str) -> tuple[int, int]:
    """'i/n' with 1 <= i <= n."""
    try:
        i, n = (int(x) for x in spec.split("/"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"--shard takes i/n, such as 2/4: {spec!r}") from None
    if not 1 <= i <= n:
        raise argparse.ArgumentTypeError(f"--shard i/n needs 1 <= i <= n: {spec!r}")
    return i, n


def shard(mutants: list, i: int, n: int) -> list:
    """Part i of n, round robin over the list: the parts are disjoint, cover the list and differ by one at most."""
    return mutants[i - 1::n]


def changed_files(base: str) -> list[str]:
    """Files changed on this branch since it left BASE (git diff BASE...HEAD), plus uncommitted changes to tracked
    files. A failing git (an unknown BASE, a shallow clone) stops the run: it must never select nothing by accident."""
    mb = subprocess.run(["git", "merge-base", base, "HEAD"], capture_output=True, text=True)
    if mb.returncode != 0:
        sys.exit(f"git merge-base {base} HEAD failed (a shallow clone needs fetch-depth: 0): {mb.stderr.strip()}")
    r = subprocess.run(["git", "diff", "--name-only", "--no-renames", mb.stdout.strip()],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"git diff against {base} failed: {r.stderr.strip()}")
    return [f for f in r.stdout.splitlines() if f]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Remove one guard at a time; the tests must fail every time.")
    ap.add_argument("--changed", metavar="BASE", help="only the mutants a change since BASE can affect")
    ap.add_argument("--shard", type=parse_shard, metavar="I/N", help="run part I of N of the (selected) mutants")
    args = ap.parse_args(argv)
    mutants = MUTANTS
    if args.changed:
        mutants, why = select_changed(MUTANTS, changed_files(args.changed))
        print(f"since {args.changed}: {why}")
    if args.shard:
        mutants = shard(mutants, *args.shard)
        print(f"shard {args.shard[0]}/{args.shard[1]}: {len(mutants)} mutants")
    env = {**os.environ, "GOTOOLCHAIN": "local"}
    survived = []
    for name, path, old, new in mutants:
        src = path.read_text(encoding="utf-8")
        if src.count(old) != 1:
            print(f"STALE  {name}: the text to mutate is not found exactly once in {path}")
            survived.append(name)
            continue
        try:
            path.write_text(src.replace(old, new), encoding="utf-8", newline="\n")
            cwd, pkg = Path("."), path.parent
            if path.parts[0] == "..":   # another module of the repository (the fleet service, decision 0026)
                cwd, pkg = Path(*path.parts[:2]), Path(*path.parts[2:]).parent
            r = subprocess.run(["go", "test", "-count=1", "./" + str(pkg).replace("\\", "/") + "/"], cwd=cwd, env=env,
                               capture_output=True, text=True)
        finally:
            path.write_text(src, encoding="utf-8", newline="\n")
        killed = r.returncode != 0 and "build failed" not in r.stdout + r.stderr
        print(("killed " if killed else "ALIVE  ") + name + ("" if killed or r.returncode == 0 else " (build failed)"))
        if not killed:
            survived.append(name)
    print(f"{len(mutants) - len(survived)}/{len(mutants)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())

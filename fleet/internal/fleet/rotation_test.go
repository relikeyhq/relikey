// SPDX-License-Identifier: EUPL-1.2

package fleet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"relikey/agent/pkg/fleetproto"
	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
	"relikey/fleet/internal/registry/regtest"
)

func hexKey(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

// rotationStatement is the desk's statement as KeyClerk's rotate_edge writes it (kc-edge-officer-v2, purpose
// rotation), signed by the desk's officer and co-signed with the edge's new key. encoding/json writes a map's names
// sorted and compact, which is the canonical form for these values.
func rotationStatement(t *testing.T, edge string, officer, next ed25519.PrivateKey) fleetproto.Statement {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"edge": edge, "format": "kc-edge-officer-v2", "officer": "idp:desk-officer",
		"officer_key": hexKey(officer), "purpose": "rotation",
		"nodes": []any{map[string]any{"enrolment_key": hexKey(next), "unlock_key": nil, "tpm": nil}}})
	if err != nil {
		t.Fatal(err)
	}
	st := fleetproto.Statement{Bytes: base64.StdEncoding.EncodeToString(raw)}
	for _, k := range []ed25519.PrivateKey{officer, next} {
		sum := sha256Hex(k)
		st.Signatures = append(st.Signatures, fleetproto.StatementSignature{Key: hexKey(k), KeyID: sum,
			Signature: hex.EncodeToString(ed25519.Sign(k, raw))})
	}
	return st
}

func sha256Hex(k ed25519.PrivateKey) string {
	sum := sha256.Sum256(k.Public().(ed25519.PublicKey))
	return hex.EncodeToString(sum[:])[:16]
}

func (g *enrolRig) handover(t *testing.T, edge string, old, next ed25519.PrivateKey) int {
	t.Helper()
	s, err := fleetproto.SignHandover(old, next, fleetproto.Handover{Edge: edge, At: time.Now(),
		Statement: rotationStatement(t, edge, key("the desk's officer"), next)})
	if err != nil {
		t.Fatal(err)
	}
	return g.post(t, "/fleet/v1/rotation", s)
}

func (g *enrolRig) reportSeq(t *testing.T, edge string, priv ed25519.PrivateKey, seq int64) int {
	t.Helper()
	signed, err := fleetproto.Sign(priv, fleetproto.Report{Edge: edge, Seq: seq, At: time.Now(), Release: "dev",
		Mode: "enforce", Profile: "basic", Serial: 1, AppliedSerial: 1, DriftCodes: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return g.post(t, "/fleet/v1/report", signed)
}

// approveRotation is an officer's approval of a pending rotation: the new key's first 20 characters as read from the
// desk's rotation record, signed with ann's passkey over the approval's statement.
func (g *enrolRig) approveRotation(r admin.Rotation, typed string) error {
	a := enrol.RotationApproval{Fleet: "fleet-1", Approver: "ann", Rotation: r.ID, Edge: r.Edge, OldKey: r.OldKey,
		NewKey: r.NewKey, Typed: typed, ReadBy: "ann", ReadHow: "desk record"}
	st := registry.Statement{Kind: "rotate", Fleet: "fleet-1", Registry: 1, Body: a.Hash(),
		Expires: time.Now().Add(5 * time.Minute), Nonce: "r-" + r.ID}
	held, _ := g.s.Held(r.Edge)
	_, err := g.st.ApproveRotation(stmtRP, a, st, g.ann.Sign(stmtRP, "ann", st, regtest.Tweak{}), held,
		admin.Event{At: time.Now(), Subject: "ann"}, time.Now())
	return err
}

// The fleet's half of a rotation (#26), for an edge configured in fleet.json: a handover without the old key's
// signature is refused; one with both keys is pending and listed, once however often it comes; reports with the old
// key are taken while it waits and the new key's are refused; an officer's passkey approval moves the fleet to the
// new key, the old key is refused from then on, and the report sequence carries across the change.
func TestARotationIsPendingUntilAnOfficerApprovesIt(t *testing.T) {
	g := newEnrolRig(t)
	old, next := key("plant-a"), key("plant-a's new key")
	base := time.Now().UnixMilli()
	if got := g.reportSeq(t, "plant-a", old, base); got != 204 {
		t.Fatalf("a report before the rotation: %d", got)
	}
	if got := g.handover(t, "plant-a", key("a thief"), next); got != 403 || len(g.st.PendingRotations()) != 0 {
		t.Fatalf("a handover without the old key's signature: %d, %d pending; want 403 and nothing pending", got,
			len(g.st.PendingRotations()))
	}
	for range 2 { // the edge sends it until it is taken: the same handover again changes nothing
		if got := g.handover(t, "plant-a", old, next); got != 204 {
			t.Fatalf("a handover signed by both keys: %d, want 204", got)
		}
	}
	pending := g.st.PendingRotations()
	if len(pending) != 1 || pending[0].NewKey != hexKey(next) || pending[0].Facts.Officer != "idp:desk-officer" {
		t.Fatalf("pending: %+v; want one rotation to the new key, with the desk's statement", pending)
	}
	if got := g.reportSeq(t, "plant-a", old, base+1); got != 204 {
		t.Fatalf("a report with the old key while the rotation waits: %d, want 204", got)
	}
	if got := g.reportSeq(t, "plant-a", next, base+2); got != 403 {
		t.Fatalf("a report with the new key before the approval: %d, want 403", got)
	}
	if err := g.approveRotation(pending[0], "0000000000000000000000"); err == nil {
		t.Fatal("an approval with characters not of the new key was taken")
	}
	if err := g.approveRotation(pending[0], hexKey(next)[:20]); err != nil {
		t.Fatalf("the officer's approval: %v", err)
	}
	if got := g.reportSeq(t, "plant-a", old, base+3); got != 403 {
		t.Fatalf("a report with the old key after the approval: %d, want 403", got)
	}
	if got := g.reportSeq(t, "plant-a", next, base+1); got != 403 {
		t.Fatalf("a replayed sequence under the new key: %d, want 403 (the sequence carries across)", got)
	}
	if got := g.reportSeq(t, "plant-a", next, base+4); got != 204 || g.state("plant-a") != "ok" {
		t.Fatalf("a report with the new key after the approval: %d, want 204", got)
	}
	if len(g.st.PendingRotations()) != 0 {
		t.Fatal("the approved rotation is still pending")
	}
	if l := g.st.Log(1); len(l) != 1 || l[0].Action != "approve rotation" || !l[0].Signed {
		t.Fatalf("the approval is not in the evidence log as signed: %+v", l)
	}
	if got := g.handover(t, "plant-a", old, next); got != 403 {
		t.Fatalf("the handover again after the approval: %d, want 403 (the fleet no longer holds the old key)", got)
	}
}

// An edge enrolled by code rotates the same way: the approval updates its slot. A rotation whose old key the fleet no
// longer holds is not approved, and a second rotation of one edge is void once the first is approved.
func TestAnEnrolledEdgeRotatesAndOtherRotationsGoVoid(t *testing.T) {
	g := newEnrolRig(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	code := g.open(t, "plant-c")
	g.post(t, "/fleet/v1/enrol", enrol.Present(code, priv))
	if err := g.approve(code.Slot, hexKey(priv)); err != nil {
		t.Fatal(err)
	}
	next, other := key("plant-c next"), key("plant-c other")
	if a, b := g.handover(t, "plant-c", priv, next), g.handover(t, "plant-c", priv, other); a != 204 || b != 204 {
		t.Fatalf("two handovers: %d, %d", a, b)
	}
	pending := g.st.PendingRotations()
	if len(pending) != 2 {
		t.Fatalf("%d pending, want both shown (two at once is an alarm, never one chosen)", len(pending))
	}
	if err := g.approveRotation(pending[0], hexKey(next)[4:24]); err != nil {
		t.Fatalf("the approval: %v", err)
	}
	if g.st.Enrolled()["plant-c"] != hexKey(next) {
		t.Fatal("the enrolled edge's slot does not hold the new key")
	}
	if r, _ := g.st.Rotation(pending[1].ID); r.State != "void" {
		t.Fatalf("the other rotation is %s, want void", r.State)
	}
	if err := g.approveRotation(pending[1], hexKey(other)[:20]); err == nil || !strings.Contains(err.Error(), "no such rotation") {
		t.Fatalf("a void rotation approved: %v", err)
	}
	if got := g.reportSeq(t, "plant-c", next, time.Now().UnixMilli()); got != 204 {
		t.Fatalf("the enrolled edge's report with its new key: %d", got)
	}
}

// A handover for an edge the fleet does not know is refused; a fleet without officers has no one to approve one.
func TestAHandoverForAnUnknownEdgeOrWithoutOfficersIsRefused(t *testing.T) {
	g := newEnrolRig(t)
	if got := g.handover(t, "plant-z", key("plant-z"), key("plant-z next")); got != 403 {
		t.Fatalf("a handover for an edge the fleet does not know: %d, want 403", got)
	}
	plain := httptest.NewServer((&Server{Inv: g.inv, Keys: keys(), Now: time.Now, Log: g.s.Log}).Handler())
	defer plain.Close()
	s, _ := fleetproto.SignHandover(key("plant-a"), key("plant-a next"), fleetproto.Handover{Edge: "plant-a", At: time.Now(),
		Statement: rotationStatement(t, "plant-a", key("the desk's officer"), key("plant-a next"))})
	b, _ := json.Marshal(s)
	resp, err := plain.Client().Post(plain.URL+"/fleet/v1/rotation", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("a fleet without officers: %d, want 404", resp.StatusCode)
	}
}

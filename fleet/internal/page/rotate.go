// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
)

// Rotation (decision 0026 point 3, #26): an edge whose enrolment key the desk rotated hands the new key over, signed
// by the old key and the new one, with the desk's rotation statement. The page lists each pending rotation with what
// the statement says, for the approver to read; the fleet cannot verify the desk's officer, so an officer of this
// fleet types at least 20 characters of the new key as the desk's rotation record (or the edge where the key was
// made) shows it, records who read it and how, and signs the approval with their officer passkey, as for an
// activation. Nothing moves before that signature.

// pendingRotation is a rotation approval an officer is signing: the statement is fixed at begin, used once at sign.
type pendingRotation struct {
	a     enrol.RotationApproval
	st    registry.Statement
	until time.Time
}

// held is the key (hex) the fleet holds for an edge now; empty when it holds none.
func (p *Page) held(edge string) string {
	if p.Held == nil {
		return ""
	}
	k, _ := p.Held(edge)
	return k
}

// rotateBegin checks a rotation approval and gives the officer the request to sign it with their own passkey.
func (p *Page) rotateBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rotation string `json:"rotation"`
		Typed    string `json:"typed"`
		ReadBy   string `json:"read_by"`
		ReadHow  string `json:"read_how"`
	}
	s, ok := p.step(w, r, &in, true)
	if !ok {
		return
	}
	reg, o, ok := p.officer(s)
	if !ok {
		fail(w, http.StatusForbidden, "only an officer approves a key rotation, with their officer passkey")
		return
	}
	rot, ok := p.Admin.Rotation(in.Rotation)
	if !ok {
		fail(w, http.StatusBadRequest, "no such rotation is waiting: reload the page")
		return
	}
	a := enrol.RotationApproval{Fleet: reg.Fleet, Approver: o.ID, Rotation: rot.ID, Edge: rot.Edge, OldKey: rot.OldKey,
		NewKey: rot.NewKey, Typed: in.Typed, ReadBy: in.ReadBy, ReadHow: in.ReadHow}
	if err := p.Admin.CheckRotation(a, p.held(rot.Edge)); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	now := p.Now()
	st := registry.Statement{Kind: "rotate", Fleet: reg.Fleet, Registry: reg.Version, Body: a.Hash(),
		Expires: now.Add(challengeTTL), Nonce: random()}
	p.mu.Lock()
	if p.rotations == nil {
		p.rotations = map[string]pendingRotation{}
	}
	prune(p.rotations, func(x pendingRotation) bool { return !now.Before(x.until) }, func(x pendingRotation) time.Time { return x.until })
	p.rotations[p.sessionID(r)] = pendingRotation{a: a, st: st, until: st.Expires}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":        b64.EncodeToString(st.Challenge()),
		"rpId":             p.rp().ID,
		"allowCredentials": []credDesc{{"public-key", o.CredentialID}},
		"userVerification": "required",
		"timeout":          ceremonyMS,
	})
}

// rotateSign takes the officer's signature over the approval begun in this session; with it the fleet holds the new
// key for the edge and refuses the old one.
func (p *Page) rotateSign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientDataJSON    string `json:"client_data_json"`
		AuthenticatorData string `json:"authenticator_data"`
		Signature         string `json:"signature"`
	}
	s, ok := p.step(w, r, &in, true)
	if !ok {
		return
	}
	p.mu.Lock()
	pr, had := p.rotations[p.sessionID(r)]
	delete(p.rotations, p.sessionID(r)) // one use, whatever the outcome
	p.mu.Unlock()
	if !had || !p.Now().Before(pr.until) || pr.a.Approver != s.sub {
		fail(w, http.StatusBadRequest, "no rotation is being approved in this session: start again")
		return
	}
	sig := registry.Signature{Officer: s.sub, ClientDataJSON: in.ClientDataJSON, AuthenticatorData: in.AuthenticatorData, Sig: in.Signature}
	ev := admin.Event{At: p.Now(), Subject: s.sub, Source: r.Header.Get("X-Forwarded-For")}
	rot, err := p.Admin.ApproveRotation(p.rp(), pr.a, pr.st, sig, p.held(pr.a.Edge), ev, p.Now())
	if err != nil {
		p.Log.Warn("rotation approval refused", "sub", s.sub, "err", err)
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	p.Log.Info("edge key rotated", "by", s.sub, "edge", rot.Edge, "new_key_fingerprint", enrol.Fingerprint(rot.NewKey))
	writeJSON(w, http.StatusOK, map[string]any{"rotated": rot.Edge})
}

// rotationRow is a pending rotation as the page shows it: the edge, both keys, and what the desk's statement says.
type rotationRow struct {
	ID, Edge, Source, Received string
	OldKeyID, NewKey           string // the new key whole, in groups, for comparing with the desk's record
	Officer, OfficerKeyID      string // as the statement names them: not verified by the fleet
	Others                     int    // other rotations of the same edge waiting: an alarm
	Stale                      bool   // the fleet no longer holds the old key: approving it would move nothing
}

func (p *Page) rotationRows() []rotationRow {
	pending := p.Admin.PendingRotations()
	perEdge := map[string]int{}
	for _, r := range pending {
		perEdge[r.Edge]++
	}
	rows := make([]rotationRow, 0, len(pending))
	for _, r := range pending {
		rows = append(rows, rotationRow{ID: r.ID, Edge: r.Edge, Source: r.Source,
			Received: r.Received.UTC().Format("2006-01-02 15:04Z"), OldKeyID: keyID(r.OldKey), NewKey: groups(r.NewKey),
			Officer: r.Facts.Officer, OfficerKeyID: keyID(r.Facts.OfficerKey), Others: perEdge[r.Edge] - 1,
			Stale: p.held(r.Edge) != r.OldKey})
	}
	return rows
}

// keyID is how the desk names a key: the first 16 hex characters of its sha256 (KeyClerk's key id).
func keyID(keyHex string) string {
	k, err := hex.DecodeString(keyHex)
	if err != nil {
		return "?"
	}
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:8])
}

// SPDX-License-Identifier: EUPL-1.2

package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"relikey/agent/pkg/fleetproto"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
)

// MaxPendingRotations caps the handovers waiting for one edge. Only a holder of the edge's current key can send one;
// more than one at a time is itself an alarm, shown on the page.
const MaxPendingRotations = 3

// Rotation is an edge's enrolment-key handover (decision 0026 point 3, #26): pending until an officer of the registry
// in force approves it, then approved, or void when another rotation of the same edge was approved first.
type Rotation struct {
	ID        string                   `json:"id"`
	Edge      string                   `json:"edge"`
	OldKey    string                   `json:"old_key"`
	NewKey    string                   `json:"new_key"`
	Facts     fleetproto.RotationFacts `json:"facts"`     // what the desk's statement says: shown, not trusted
	Statement fleetproto.Statement     `json:"statement"` // kept whole, as evidence
	Received  time.Time                `json:"received"`
	Source    string                   `json:"source,omitempty"`
	State     string                   `json:"state"` // pending, approved or void
	Decided   time.Time                `json:"decided,omitzero"`
}

func rotationID(edge, oldKey, newKey string) string {
	sum := sha256.Sum256([]byte("relikey-fleet-rotation-id\n" + edge + "\n" + oldKey + "\n" + newKey))
	return hex.EncodeToString(sum[:16])
}

// Handover records a verified handover as pending (fleetproto.VerifyHandover checked it against the key held for the
// edge). The same handover again changes nothing, so the edge may send it until it is taken. It is logged: shown,
// never silent.
func (s *Store) Handover(h fleetproto.Handover, f fleetproto.RotationFacts, source string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Versions) == 0 {
		return errors.New("the fleet has no officers yet, so no one can approve a rotation: anchor it first")
	}
	id := rotationID(h.Edge, h.OldKey, h.NewKey)
	pending := 0
	for _, r := range s.d.Rotations {
		if r.ID == id && r.State == "pending" {
			return nil
		}
		if r.Edge == h.Edge && r.State == "pending" {
			pending++
		}
	}
	ev := Event{At: now, Subject: "edge:" + h.Edge, Source: source, Action: "hand over key"}
	if pending >= MaxPendingRotations {
		ev.Detail = fmt.Sprintf("refused: %d rotations of this edge are waiting already; new key fingerprint %s",
			pending, enrol.Fingerprint(h.NewKey))
		s.d.Log = append(s.d.Log, ev)
		if err := s.save(); err != nil {
			return err
		}
		return fmt.Errorf("%s: %d rotations are waiting already", h.Edge, pending)
	}
	s.d.Rotations = append(s.d.Rotations, Rotation{ID: id, Edge: h.Edge, OldKey: h.OldKey, NewKey: h.NewKey, Facts: f,
		Statement: h.Statement, Received: now, Source: source, State: "pending"})
	ev.Detail = fmt.Sprintf("pending approval: old key fingerprint %s, new key fingerprint %s, desk officer %s",
		enrol.Fingerprint(h.OldKey), enrol.Fingerprint(h.NewKey), f.Officer)
	if pending > 0 {
		ev.Detail += fmt.Sprintf("; %d other rotation(s) of this edge are waiting too", pending)
	}
	s.d.Log = append(s.d.Log, ev)
	return s.save()
}

// PendingRotations are the rotations waiting for an officer, oldest first.
func (s *Store) PendingRotations() []Rotation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Rotation
	for _, r := range s.d.Rotations {
		if r.State == "pending" {
			out = append(out, r)
		}
	}
	return out
}

// ApprovedRotations are the approved rotations in the order they were approved: an edge configured in fleet.json
// under its old key is held under the new one from then on (the slots of edges enrolled by code are updated).
func (s *Store) ApprovedRotations() []Rotation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Rotation
	for _, r := range s.d.Rotations {
		if r.State == "approved" {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b Rotation) int { return a.Decided.Compare(b.Decided) })
	return out
}

// Rotation is one rotation by id.
func (s *Store) Rotation(id string) (Rotation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.d.Rotations, func(r Rotation) bool { return r.ID == id })
	if i < 0 {
		return Rotation{}, false
	}
	return s.d.Rotations[i], true
}

// CheckRotation is whether an approval would pass, before an officer is asked to sign it. held is the key (hex) the
// fleet holds for the edge now.
func (s *Store) CheckRotation(a enrol.RotationApproval, held string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.checkRotation(a, held)
	return err
}

func (s *Store) checkRotation(a enrol.RotationApproval, held string) (int, error) {
	i := slices.IndexFunc(s.d.Rotations, func(r Rotation) bool { return r.ID == a.Rotation })
	switch {
	case i < 0 || s.d.Rotations[i].State != "pending":
		return -1, errors.New("no such rotation is waiting: reload the page")
	case s.d.Rotations[i].Edge != a.Edge || s.d.Rotations[i].OldKey != a.OldKey || s.d.Rotations[i].NewKey != a.NewKey:
		return -1, errors.New("the approval does not name the rotation's edge and keys")
	case held != a.OldKey:
		return -1, fmt.Errorf("%s: the fleet no longer holds the old key this rotation replaces, so it would move "+
			"nothing; the edge hands its current key over again", a.Edge)
	}
	return i, enrol.CheckRotation(a)
}

// ApproveRotation records a rotation one officer's passkey approved, verified here against the registry in force:
// from then on the fleet holds the new key for the edge and refuses the old one. Other rotations of the same edge
// become void. Refused or not, it is logged. held is the key (hex) the fleet holds for the edge now.
func (s *Store) ApproveRotation(rp registry.RP, a enrol.RotationApproval, st registry.Statement, sig registry.Signature,
	held string, ev Event, now time.Time) (Rotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, ok := s.current(now)
	if !ok {
		return Rotation{}, errors.New("the fleet has no officers yet: anchor it first")
	}
	err := enrol.ApproveRotation(rp, reg, a, st, sig, now)
	i := -1
	if err == nil {
		i, err = s.checkRotation(a, held)
	}
	ev.Action = "approve rotation"
	if err != nil {
		ev.Detail = "refused: " + err.Error()
		s.d.Log = append(s.d.Log, ev)
		if serr := s.save(); serr != nil {
			return Rotation{}, serr
		}
		return Rotation{}, err
	}
	r := &s.d.Rotations[i]
	r.State, r.Decided = "approved", now
	for j := range s.d.Rotations {
		if o := &s.d.Rotations[j]; o.Edge == r.Edge && o.State == "pending" {
			o.State, o.Decided = "void", now
		}
	}
	for id, sl := range s.d.Slots {
		if sl.Active && sl.Name == r.Edge && sl.Key == r.OldKey {
			sl.Key = r.NewKey
			s.d.Slots[id] = sl
		}
	}
	ev.Signed = true
	ev.Detail = fmt.Sprintf("under registry %d, rotation %s of %s: old key fingerprint %s, new key fingerprint %s, "+
		"read by %s, %s", reg.Version, a.Hash(), r.Edge, enrol.Fingerprint(r.OldKey), enrol.Fingerprint(r.NewKey),
		a.ReadBy, a.ReadHow)
	s.d.Log = append(s.d.Log, ev)
	return *r, s.save()
}

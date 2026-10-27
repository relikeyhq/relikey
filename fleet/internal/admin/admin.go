// SPDX-License-Identifier: EUPL-1.2

// Package admin is the fleet's administrative state (decision 0026 points 14-33): the officer registry chain, the
// enrolment slots, and the evidence log of every action (point 26). One JSON file, replaced atomically. It holds
// statements and their outcomes; it never holds a key that can approve anything (point 14).
package admin

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
)

// Version is one accepted registry and when it takes effect.
type Version struct {
	Registry   registry.Registry `json:"registry"`
	Effective  time.Time         `json:"effective"`
	BreakGlass bool              `json:"break_glass,omitempty"`
	Change     *registry.Change  `json:"change,omitempty"` // the statement and signatures that carried it, as evidence
}

// Event is one line of the evidence log: who did what, from where, with what outcome.
type Event struct {
	At      time.Time `json:"at"`
	Subject string    `json:"subject"` // the broker subject, or "edge:<slot>" for an edge's presentation
	Session string    `json:"session,omitempty"`
	Source  string    `json:"source,omitempty"`
	Action  string    `json:"action"`
	Detail  string    `json:"detail,omitempty"`
	Signed  bool      `json:"signed"` // carried by a passkey statement (point 14), or a session alone
}

type data struct {
	Fleet    string                `json:"fleet"`
	Versions []Version             `json:"versions"`
	Slots    map[string]enrol.Slot `json:"slots"`
	Log      []Event               `json:"log"`
	// The anchor ceremony (point 30): the passkeys the first officers registered, by broker subject, and the
	// version 1 they are signing. Both go once the fleet is anchored.
	Candidates map[string]registry.Officer `json:"candidates,omitempty"`
	Draft      *registry.Change            `json:"draft,omitempty"`
}

// Store is the fleet's administrative state.
type Store struct {
	path string
	mu   sync.Mutex
	d    data
}

// Open loads the state, or starts it for a fleet.
func Open(path, fleet string) (*Store, error) {
	s := &Store{path: path, d: data{Fleet: fleet, Slots: map[string]enrol.Slot{}}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.d.Fleet != fleet {
		return nil, fmt.Errorf("%s holds fleet %q, not %q: a re-anchored fleet is a new identity (point 30)", path, s.d.Fleet, fleet)
	}
	if s.d.Slots == nil {
		s.d.Slots = map[string]enrol.Slot{}
	}
	return s, nil
}

func (s *Store) save() error {
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, filepath.Clean(s.path))
}

// Fleet is this fleet's id.
func (s *Store) Fleet() string { return s.d.Fleet }

// Anchor is the anchor registry's hash, empty before the fleet is anchored.
func (s *Store) Anchor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Versions) == 0 {
		return ""
	}
	return s.d.Versions[0].Registry.Hash()
}

// Current is the registry in force at now: the newest version whose delay has passed.
func (s *Store) Current(now time.Time) (registry.Registry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.d.Versions) - 1; i >= 0; i-- {
		if !now.Before(s.d.Versions[i].Effective) {
			return s.d.Versions[i].Registry, true
		}
	}
	return registry.Registry{}, false
}

// SetAnchor records an anchor already verified by registry.Anchor. Refused once anchored.
func (s *Store) SetAnchor(a registry.Accepted, c registry.Change, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setAnchor(a, c, ev)
}

func (s *Store) setAnchor(a registry.Accepted, c registry.Change, ev Event) error {
	if len(s.d.Versions) > 0 {
		return errors.New("the fleet is anchored already: a new anchor is a new fleet (point 30)")
	}
	s.d.Versions = append(s.d.Versions, Version{Registry: a.Registry, Effective: a.Effective, Change: &c})
	s.d.Log = append(s.d.Log, ev)
	return s.save()
}

// DraftTTL is how long a drafted anchor can be signed; after it a new draft needs every signature again.
const DraftTTL = 24 * time.Hour

var errAnchored = errors.New("the fleet is anchored already: officers change through the registry (two officers' passkeys)")

// Register records a first officer's passkey for the anchor (point 30); the caller has verified the registration
// and that the person is named for the anchor. Registering again replaces that person's passkey and voids the draft:
// the list the others signed has changed.
func (s *Store) Register(o registry.Officer, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Versions) > 0 {
		return errAnchored
	}
	for id, c := range s.d.Candidates {
		if id != o.ID && c.CredentialID == o.CredentialID {
			return errors.New("this passkey is registered for another officer already: each officer brings their own")
		}
		if id != o.ID && c.Name == o.Name {
			// officers are named by broker username: a second account under that name (a rename, or someone holding
			// the broker's admin) never replaces or joins the first; the officers and the broker's admin sort it out
			return fmt.Errorf("a different broker account registered as %s already: if that was not you, tell the other officers and the broker's administrator", o.Name)
		}
	}
	if s.d.Candidates == nil {
		s.d.Candidates = map[string]registry.Officer{}
	}
	_, again := s.d.Candidates[o.ID]
	s.d.Candidates[o.ID] = o
	ev.Action, ev.Detail = "register officer passkey", fmt.Sprintf("%s, device-bound %v", o.Name, o.DeviceBound)
	if again {
		ev.Action = "replace officer passkey"
	}
	if s.d.Draft != nil {
		s.d.Draft = nil
		ev.Detail += "; the drafted anchor is void, every officer signs the new one"
	}
	s.d.Log = append(s.d.Log, ev)
	return s.save()
}

// Candidates are the registered first officers' passkeys, by name.
func (s *Store) Candidates() []registry.Officer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]registry.Officer, 0, len(s.d.Candidates))
	for _, o := range s.d.Candidates {
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b registry.Officer) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Draft is the anchor to sign: version 1 of the named officers' passkeys, once every named officer has registered
// one, and the signatures so far. A draft past its expiry is replaced, its signatures void. nonce makes a new
// draft's statement unique.
func (s *Store) Draft(named []string, nonce string, now time.Time) (registry.Change, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Versions) > 0 {
		return registry.Change{}, false, errAnchored
	}
	if s.d.Draft != nil && now.Before(s.d.Draft.Statement.Expires) {
		return *s.d.Draft, true, nil
	}
	byName := map[string]registry.Officer{}
	for _, o := range s.d.Candidates {
		byName[o.Name] = o
	}
	var officers []registry.Officer
	for _, name := range named {
		o, ok := byName[name]
		if !ok {
			return registry.Change{}, false, nil // someone has not registered yet
		}
		officers = append(officers, o)
	}
	slices.SortFunc(officers, func(a, b registry.Officer) int { return strings.Compare(a.ID, b.ID) })
	r := registry.Registry{Fleet: s.d.Fleet, Version: 1, Officers: officers}
	c := registry.Change{Registry: r, Statement: registry.Statement{Kind: "registry", Fleet: s.d.Fleet, Registry: 1,
		Body: r.Hash(), Expires: now.Add(DraftTTL), Nonce: nonce}}
	s.d.Draft = &c
	s.d.Log = append(s.d.Log, Event{At: now, Subject: "fleet", Action: "draft anchor",
		Detail: fmt.Sprintf("version 1, %d officers, hash %s, signable until %s", len(officers), r.Hash(), c.Statement.Expires.Format(time.RFC3339))})
	return c, true, s.save()
}

// SignAnchor adds one officer's signature over the drafted anchor, verified here; with the last one the anchor is
// verified whole (registry.Anchor) and recorded. It returns whether the fleet is now anchored.
func (s *Store) SignAnchor(rp registry.RP, sig registry.Signature, ev Event, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Versions) > 0 {
		return false, errAnchored
	}
	d := s.d.Draft
	if d == nil || !now.Before(d.Statement.Expires) {
		return false, errors.New("no anchor is being signed: reload the page for the current draft")
	}
	i := slices.IndexFunc(d.Registry.Officers, func(o registry.Officer) bool { return o.ID == sig.Officer })
	if i < 0 {
		return false, errors.New("you are not one of the officers this anchor names")
	}
	if _, err := rp.Verify(sig, d.Registry.Officers[i], d.Statement, now); err != nil {
		return false, fmt.Errorf("your signature did not verify: %w", err)
	}
	d.Signatures = slices.DeleteFunc(d.Signatures, func(x registry.Signature) bool { return x.Officer == sig.Officer })
	d.Signatures = append(d.Signatures, sig)
	ev.Action, ev.Signed = "sign anchor", true
	ev.Detail = fmt.Sprintf("%d of %d signed", len(d.Signatures), len(d.Registry.Officers))
	s.d.Log = append(s.d.Log, ev)
	if len(d.Signatures) < len(d.Registry.Officers) {
		return false, s.save()
	}
	acc, err := registry.Anchor(rp, *d, now)
	if err != nil {
		_ = s.save()
		return false, fmt.Errorf("the anchor did not verify whole: %w", err)
	}
	done := Event{At: now, Subject: "fleet", Action: "anchored", Signed: true,
		Detail: fmt.Sprintf("version 1, hash %s, %d officers each signed", acc.Registry.Hash(), len(d.Registry.Officers))}
	c := *d
	s.d.Draft, s.d.Candidates = nil, nil
	return true, s.setAnchor(acc, c, done)
}

// Slots are the slots, newest first.
func (s *Store) Slots() []enrol.Slot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]enrol.Slot, 0, len(s.d.Slots))
	for _, sl := range s.d.Slots {
		out = append(out, sl)
	}
	slices.SortFunc(out, func(a, b enrol.Slot) int { return b.OpenedAt.Compare(a.OpenedAt) })
	return out
}

// OpenSlot opens a slot (a session action: it reduces nothing and grants nothing, point 14) and logs it. The code
// it returns carries the single-use secret: shown once, never stored.
func (s *Store) OpenSlot(url, pin, name string, kind enrol.Kind, profile string, ev Event, now time.Time) (enrol.Slot, enrol.Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Versions) == 0 {
		return enrol.Slot{}, enrol.Code{}, errors.New("the fleet has no officers yet: anchor it first")
	}
	open := make([]enrol.Slot, 0, len(s.d.Slots))
	for _, sl := range s.d.Slots {
		open = append(open, sl)
	}
	sl, code, err := enrol.Open(s.d.Fleet, url, pin, s.d.Versions[0].Registry.Hash(), name, kind, profile, ev.Subject, open, now)
	if err != nil {
		return enrol.Slot{}, enrol.Code{}, err
	}
	s.d.Slots[sl.ID] = sl
	ev.Action, ev.Detail = "open slot", fmt.Sprintf("%s (%s, %s), expires %s", name, kind, profile, sl.Expires.Format(time.RFC3339))
	s.d.Log = append(s.d.Log, ev)
	return sl, code, s.save()
}

// Present takes an edge's presentation for its slot; refusals are kept on the slot and logged (shown, never silent).
func (s *Store) Present(p enrol.Presentation, source string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sl, ok := s.d.Slots[p.Slot]
	if !ok {
		return errors.New("no such slot")
	}
	next, err := enrol.Accept(s.d.Fleet, sl, p, now)
	s.d.Slots[sl.ID] = next
	ev := Event{At: now, Subject: "edge:" + sl.Name, Source: source, Action: "present key"}
	if err != nil {
		ev.Detail = "refused: " + err.Error()
	} else {
		ev.Detail = "fingerprint " + enrol.Fingerprint(next.Key)
	}
	s.d.Log = append(s.d.Log, ev)
	if serr := s.save(); serr != nil {
		return serr
	}
	return err
}

// Log is the evidence log, newest first, at most n entries.
func (s *Store) Log(n int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.d.Log)
	slices.Reverse(out)
	return out[:min(n, len(out))]
}

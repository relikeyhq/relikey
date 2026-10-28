// SPDX-License-Identifier: EUPL-1.2

package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
	"relikey/fleet/internal/registry/regtest"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// anchored opens a store with an anchor (the ceremony that verifies it is W2's; here it is set as already verified).
func anchored(t *testing.T) (*Store, string) {
	path := filepath.Join(t.TempDir(), "admin.json")
	s, err := Open(path, "fleet-1")
	if err != nil {
		t.Fatal(err)
	}
	r := registry.Registry{Fleet: "fleet-1", Version: 1, Officers: []registry.Officer{{ID: "ann"}, {ID: "bob"}, {ID: "cat"}}}
	if err := s.SetAnchor(registry.Accepted{Registry: r, Effective: t0}, registry.Change{Registry: r}, Event{At: t0, Subject: "install", Signed: true}); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestSlotsNeedAnAnchorAndSurviveARestart(t *testing.T) {
	bare, _ := Open(filepath.Join(t.TempDir(), "a.json"), "fleet-1")
	if _, _, err := bare.OpenSlot("https://f/e", strings.Repeat("a", 64), "plant-a", enrol.Edge, "basic", Event{Subject: "ann"}, t0); err == nil {
		t.Fatal("a slot opened on a fleet with no officers")
	}
	s, path := anchored(t)
	sl, code, err := s.OpenSlot("https://f/e", strings.Repeat("a", 64), "plant-a", enrol.Edge, "basic", Event{Subject: "ann", Source: "10.0.0.5"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if code.Anchor != s.Anchor() || sl.SecretHash == "" || strings.Contains(sl.SecretHash, code.Secret) {
		t.Fatal("the code does not carry the anchor, or the secret is stored")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.Present(enrol.Present(code, priv), "10.0.0.9", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, "fleet-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Slots(); len(got) != 1 || got[0].Key == "" {
		t.Fatalf("slots after a restart: %+v", got)
	}
	log := again.Log(10)
	if len(log) < 3 || log[0].Action != "present key" || log[1].Action != "open slot" || log[1].Subject != "ann" || log[1].Signed {
		t.Fatalf("evidence log: %+v", log)
	}
	if _, err := Open(path, "fleet-2"); err == nil {
		t.Fatal("another fleet's state was opened: a re-anchored fleet is a new identity")
	}
}

func TestASecondAnchorAndASecondKeyAreRefused(t *testing.T) {
	s, _ := anchored(t)
	r := registry.Registry{Fleet: "fleet-1", Version: 1}
	if err := s.SetAnchor(registry.Accepted{Registry: r}, registry.Change{}, Event{}); err == nil {
		t.Fatal("a second anchor")
	}
	_, code, _ := s.OpenSlot("https://f/e", strings.Repeat("a", 64), "plant-a", enrol.Edge, "basic", Event{Subject: "ann"}, t0)
	_, k1, _ := ed25519.GenerateKey(rand.Reader)
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	_ = s.Present(enrol.Present(code, k1), "", t0)
	if err := s.Present(enrol.Present(code, k2), "10.6.6.6", t0); !errors.Is(err, enrol.ErrTaken) {
		t.Fatalf("a second key: %v", err)
	}
	if sl := s.Slots()[0]; len(sl.Refused) == 0 || s.Log(1)[0].Detail == "" || !strings.Contains(s.Log(1)[0].Detail, "refused") {
		t.Fatal("the second key was not recorded on the slot and in the log")
	}
}

var rp = registry.RP{ID: "fleet.example", Origin: "https://fleet.example"}

type person struct {
	id, name string
	key      *regtest.Authenticator
}

func people(algs ...string) []person {
	var ps []person
	for i, alg := range algs {
		n := []string{"ann", "bob", "cat", "dan"}[i]
		ps = append(ps, person{id: "sub-" + n, name: n, key: regtest.New(alg, i == 1)})
	}
	return ps
}

func (p person) register(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Register(p.key.Officer(p.id, p.name), Event{At: t0, Subject: p.id}); err != nil {
		t.Fatal(err)
	}
}

func TestTheAnchorCeremony(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	s, _ := Open(path, "fleet-1")
	ps := people("es256", "eddsa", "rs256")
	named := []string{"ann", "bob", "cat"}
	ps[0].register(t, s)
	ps[1].register(t, s)
	if _, ok, err := s.Draft(named, "n1", t0); ok || err != nil {
		t.Fatalf("a draft before every named officer registered: %v %v", ok, err)
	}
	ps[2].register(t, s)
	d, ok, err := s.Draft(named, "n1", t0)
	if !ok || err != nil || len(d.Registry.Officers) != 3 || d.Statement.Body != d.Registry.Hash() {
		t.Fatalf("draft: %v %v %+v", ok, err, d)
	}
	if again, _, _ := s.Draft(named, "n2", t0.Add(time.Hour)); again.Statement.Nonce != "n1" {
		t.Fatal("the draft changed while it could be signed: the officers would sign different statements")
	}
	for i, p := range ps {
		done, err := s.SignAnchor(rp, p.key.Sign(rp, p.id, d.Statement, regtest.Tweak{}), Event{At: t0, Subject: p.id}, t0.Add(time.Minute))
		if err != nil || done != (i == 2) {
			t.Fatalf("%s signs: done %v err %v", p.name, done, err)
		}
	}
	if s.Anchor() != d.Registry.Hash() || len(s.Candidates()) != 0 {
		t.Fatal("not anchored, or the candidates linger")
	}
	re, err := Open(path, "fleet-1")
	if err != nil || re.Anchor() != d.Registry.Hash() {
		t.Fatalf("the anchor did not survive a restart: %v", err)
	}
	var acts []string
	for _, e := range re.Log(20) {
		acts = append(acts, e.Action)
	}
	if got := strings.Join(acts, ","); got != "anchored,sign anchor,sign anchor,sign anchor,draft anchor,register officer passkey,register officer passkey,register officer passkey" {
		t.Fatalf("evidence log: %s", got)
	}
	if err := s.Register(ps[0].key.Officer("sub-dan", "dan"), Event{}); err == nil {
		t.Fatal("a passkey registered after the anchor, outside the registry")
	}
	if _, err := s.SignAnchor(rp, ps[0].key.Sign(rp, ps[0].id, d.Statement, regtest.Tweak{}), Event{}, t0); err == nil {
		t.Fatal("an anchor signature taken after the anchor")
	}
}

func TestAnchorSignaturesThatMustBeRefused(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	ps := people("es256", "es256", "es256", "es256")
	for _, p := range ps {
		p.register(t, s)
	}
	named := []string{"ann", "bob", "cat"} // dan registered but is not named: not in the anchor
	d, _, _ := s.Draft(named, "n1", t0)
	now := t0.Add(time.Minute)
	try := func(sig registry.Signature, at time.Time) error {
		_, err := s.SignAnchor(rp, sig, Event{At: at}, at)
		return err
	}
	if err := try(ps[3].key.Sign(rp, ps[3].id, d.Statement, regtest.Tweak{}), now); err == nil || !strings.Contains(err.Error(), "not one of the officers") {
		t.Errorf("an unnamed officer signed: %v", err)
	}
	if err := try(ps[1].key.Sign(rp, ps[0].id, d.Statement, regtest.Tweak{}), now); err == nil || !strings.Contains(err.Error(), "did not verify") {
		t.Errorf("bob's passkey signed as ann: %v", err)
	}
	other := d.Statement
	other.Nonce = "other"
	if err := try(ps[0].key.Sign(rp, ps[0].id, other, regtest.Tweak{}), now); err == nil {
		t.Error("a signature over another statement was taken")
	}
	if err := try(ps[0].key.Sign(rp, ps[0].id, d.Statement, regtest.Tweak{Origin: "https://evil.example"}), now); err == nil {
		t.Error("a signature made on another origin was taken")
	}
	// signing twice counts once
	for range 2 {
		if err := try(ps[0].key.Sign(rp, ps[0].id, d.Statement, regtest.Tweak{}), now); err != nil {
			t.Fatal(err)
		}
	}
	if done, err := s.SignAnchor(rp, ps[1].key.Sign(rp, ps[1].id, d.Statement, regtest.Tweak{}), Event{}, now); done || err != nil {
		t.Fatalf("ann's second signature counted twice (done %v, err %v)", done, err)
	}
	// the draft expires: a signature after it is refused, and the next draft starts over with no signatures
	late := t0.Add(DraftTTL)
	if err := try(ps[2].key.Sign(rp, ps[2].id, d.Statement, regtest.Tweak{}), late); err == nil || !strings.Contains(err.Error(), "no anchor is being signed") {
		t.Errorf("a signature over an expired draft: want the draft named as gone, got %v", err)
	}
	nd, _, _ := s.Draft(named, "n2", late)
	if nd.Statement.Nonce != "n2" || len(nd.Signatures) != 0 {
		t.Fatalf("the new draft kept the old one's signatures or nonce: %+v", nd.Statement)
	}
}

func TestRegisteringAgainVoidsTheDraftAndOnePasskeyServesOneOfficer(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	ps := people("es256", "es256", "es256")
	for _, p := range ps {
		p.register(t, s)
	}
	named := []string{"ann", "bob", "cat"}
	d, _, _ := s.Draft(named, "n1", t0)
	if _, err := s.SignAnchor(rp, ps[0].key.Sign(rp, ps[0].id, d.Statement, regtest.Tweak{}), Event{}, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ps[0].key.Officer(ps[1].id, "bob"), Event{}); err == nil {
		t.Fatal("ann's passkey registered for bob as well")
	}
	if err := s.Register(regtest.New("es256", false).Officer("sub-mallory", "bob"), Event{}); err == nil || !strings.Contains(err.Error(), "different broker account") {
		t.Fatalf("a second account named bob registered: %v", err)
	}
	nb := regtest.New("eddsa", false)
	if err := s.Register(nb.Officer(ps[1].id, "bob"), Event{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignAnchor(rp, ps[2].key.Sign(rp, ps[2].id, d.Statement, regtest.Tweak{}), Event{}, t0); err == nil {
		t.Fatal("a signature over the voided draft was taken")
	}
	nd, _, _ := s.Draft(named, "n2", t0)
	if len(nd.Signatures) != 0 || nd.Registry.Hash() == d.Registry.Hash() {
		t.Fatal("the new draft kept signatures over the old list, or did not carry bob's new passkey")
	}
}

// An activation enrols a presented key only once an officer's passkey signs it; an enrolled name opens no new slot
// and is never activated under a second key, even where two presented slots carry the name.
func TestActivationEnrolsOnceAndNeverUnderASecondKey(t *testing.T) {
	ann := regtest.New("es256", false)
	s, _ := Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	r := registry.Registry{Fleet: "fleet-1", Version: 1, Officers: []registry.Officer{ann.Officer("ann", "ann"),
		regtest.New("es256", false).Officer("bob", "bob"), regtest.New("es256", false).Officer("cat", "cat")}}
	_ = s.SetAnchor(registry.Accepted{Registry: r, Effective: t0}, registry.Change{Registry: r}, Event{At: t0})
	rp := registry.RP{ID: "fleet.example", Origin: "https://fleet.example"}
	activate := func(slot, key string) error {
		fp := enrol.Fingerprint(key)
		flat := strings.ReplaceAll(fp, " ", "")
		a := enrol.Activation{Fleet: "fleet-1", Approver: "ann", Items: []enrol.Item{{Slot: slot, Fingerprint: fp, Typed: flat[:16],
			ReadBy: "ann", ReadHow: "on site"}}}
		st := registry.Statement{Kind: "activate", Fleet: "fleet-1", Registry: 1, Body: a.Hash(), Expires: t0.Add(time.Hour), Nonce: slot}
		_, err := s.Activate(rp, a, st, ann.Sign(rp, "ann", st, regtest.Tweak{}), Event{Subject: "ann"}, t0.Add(time.Minute))
		return err
	}
	_, code, _ := s.OpenSlot("https://f/e", strings.Repeat("a", 64), "plant-a", enrol.Edge, "basic", Event{Subject: "ann"}, t0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := enrol.Present(code, priv)
	_ = s.Present(p, "10.0.0.9", t0)
	if len(s.Enrolled()) != 0 {
		t.Fatal("a presented key is enrolled before any officer activated it")
	}
	// a second presented slot of the same name (as an older state could hold): its activation must be refused
	twin := s.d.Slots[code.Slot]
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	twin.ID, twin.Key = "twin", enrol.Present(code, other).Key
	s.d.Slots["twin"] = twin
	if err := activate(code.Slot, p.Key); err != nil {
		t.Fatalf("activation refused: %v", err)
	}
	if got := s.Enrolled(); got["plant-a"] != p.Key {
		t.Fatalf("enrolled: %v", got)
	}
	if err := activate("twin", twin.Key); err == nil || s.Enrolled()["plant-a"] != p.Key {
		t.Fatalf("an enrolled name was activated under a second key: %v", err)
	}
	delete(s.d.Slots, "twin") // no open slot of the name is left: only the enrolment refuses the new one
	if _, _, err := s.OpenSlot("https://f/e", strings.Repeat("a", 64), "plant-a", enrol.Edge, "basic", Event{Subject: "bob"}, t0.Add(time.Hour)); err == nil {
		t.Fatal("an enrolled name opened a new slot")
	}
}

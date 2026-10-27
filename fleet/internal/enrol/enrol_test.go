// SPDX-License-Identifier: EUPL-1.2

package enrol

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"relikey/fleet/internal/registry"
)

var (
	t0  = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	rp  = registry.RP{ID: "fleet.example", Origin: "https://fleet.example"}
	pin = strings.Repeat("a", 64)
	anc = strings.Repeat("b", 64)
)

// passkey is a test officer's ES256 passkey, device-bound, user verified.
type passkey struct {
	id  string
	key *ecdsa.PrivateKey
}

func newPasskey(id string) passkey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return passkey{id, k}
}

func (p passkey) officer() registry.Officer {
	raw, _ := p.key.PublicKey.Bytes()
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:]})
	enc := base64.RawURLEncoding.EncodeToString
	return registry.Officer{ID: p.id, Name: p.id, CredentialID: enc([]byte("c-" + p.id)), PublicKey: enc(cose), DeviceBound: true}
}

func (p passkey) sign(st registry.Statement) registry.Signature {
	enc := base64.RawURLEncoding.EncodeToString
	cdj, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": enc(st.Challenge()), "origin": rp.Origin})
	h := sha256.Sum256([]byte(rp.ID))
	ad := append(h[:], 0x05, 0, 0, 0, 1) // UP | UV
	c := sha256.Sum256(cdj)
	d := sha256.Sum256(append(append([]byte{}, ad...), c[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, p.key, d[:])
	return registry.Signature{Officer: p.id, ClientDataJSON: enc(cdj), AuthenticatorData: enc(ad), Sig: enc(sig)}
}

// world: a registry of three officers and a presented edge slot.
type world struct {
	reg   registry.Registry
	ann   passkey
	slots map[string]Slot
}

func newWorld(t *testing.T) *world {
	w := &world{ann: newPasskey("ann"), slots: map[string]Slot{}}
	w.reg = registry.Registry{Fleet: "fleet-1", Version: 3, Officers: []registry.Officer{w.ann.officer(), newPasskey("bob").officer(), newPasskey("cat").officer()}}
	return w
}

func (w *world) present(t *testing.T, name string, kind Kind) (Slot, ed25519.PrivateKey) {
	s, code, err := Open("fleet-1", "https://fleet.example/enrol", pin, anc, name, kind, "basic", "opener", nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCode(code.String())
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err = Accept("fleet-1", s, Present(parsed, priv), t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	w.slots[s.ID] = s
	return s, priv
}

func (w *world) activate(a Activation) ([]Slot, error) {
	st := registry.Statement{Kind: "activate", Fleet: "fleet-1", Registry: w.reg.Version, Body: a.Hash(), Expires: t0.Add(time.Hour), Nonce: "n"}
	return Activate(rp, w.reg, w.slots, a, st, w.ann.sign(st), t0.Add(2*time.Minute))
}

func item(s Slot, typed int, readBy, how string) Item {
	fp := Fingerprint(s.Key)
	return Item{Slot: s.ID, Fingerprint: fp, Typed: plain(fp)[len(plain(fp))-typed:], ReadBy: readBy, ReadHow: how}
}

func TestAnEdgeIsEnrolledByCodeKeyAndOnePasskey(t *testing.T) {
	w := newWorld(t)
	s, _ := w.present(t, "plant-a", Edge)
	got, err := w.activate(Activation{Fleet: "fleet-1", Approver: "ann", Items: []Item{item(s, 16, "the installer, Joe", "phone")}})
	if err != nil || len(got) != 1 || !got[0].Active {
		t.Fatalf("activation: %v %v", got, err)
	}
}

func TestPresentationsThatMustBeRefused(t *testing.T) {
	s, code, _ := Open("fleet-1", "https://fleet.example/enrol", pin, anc, "plant-a", Edge, "basic", "opener", nil, t0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	good := Present(code, priv)
	wrongSecret := code
	wrongSecret.Secret = "guessed"
	stolenKey := good
	stolenKey.Key = Present(code, other).Key // someone else's public key, without its private half
	for name, c := range map[string]struct {
		p  Presentation
		at time.Time
	}{
		"a wrong secret":           {Present(wrongSecret, priv), t0},
		"another's key (no proof)": {stolenKey, t0},
		"after the slot expired":   {good, t0.Add(SlotLife)},
	} {
		if _, err := Accept("fleet-1", s, c.p, c.at); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	taken, err := Accept("fleet-1", s, good, t0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Accept("fleet-1", taken, Present(code, other), t0)
	if err != ErrTaken || len(again.Refused) == 0 {
		t.Fatalf("a second key for a used slot: %v, refused %v", err, again.Refused)
	}
}

func TestActivationsThatMustBeRefused(t *testing.T) {
	w := newWorld(t)
	s, _ := w.present(t, "plant-a", Edge)
	relay, _ := w.present(t, "relay-north", Relay)
	other, _ := w.present(t, "plant-b", Edge)
	wrongFP := item(other, 16, "Joe", "phone") // the other key's fingerprint, typed consistently from it
	wrongFP.Slot = s.ID                        // ... but for this slot, whose key is another
	tooMany := Activation{Fleet: "fleet-1", Approver: "ann"}
	for i := range MaxBatch + 1 {
		extra, _ := w.present(t, "batch-"+string(rune('a'+i)), Edge)
		tooMany.Items = append(tooMany.Items, item(extra, 16, "Joe", "phone"))
	}
	for name, a := range map[string]Activation{
		"a short typed check":           {Fleet: "fleet-1", Approver: "ann", Items: []Item{item(s, 12, "Joe", "phone")}},
		"another key's fingerprint":     {Fleet: "fleet-1", Approver: "ann", Items: []Item{wrongFP}},
		"no reader recorded":            {Fleet: "fleet-1", Approver: "ann", Items: []Item{item(s, 16, "", "")}},
		"a relay read by phone":         {Fleet: "fleet-1", Approver: "ann", Items: []Item{item(relay, 16, "Joe", "phone")}},
		"a relay read by someone else":  {Fleet: "fleet-1", Approver: "ann", Items: []Item{item(relay, 16, "bob", "on site")}},
		"more than ten":                 tooMany,
		"a slot twice":                  {Fleet: "fleet-1", Approver: "ann", Items: []Item{item(s, 16, "Joe", "phone"), item(s, 16, "Joe", "phone")}},
		"an approver who is no officer": {Fleet: "fleet-1", Approver: "mallory", Items: []Item{item(s, 16, "Joe", "phone")}},
	} {
		if _, err := w.activate(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := w.activate(Activation{Fleet: "fleet-1", Approver: "ann", Items: []Item{item(relay, 16, "ann", "on site")}}); err != nil {
		t.Fatalf("a relay read on site by the approver: %v", err)
	}
}

// The page shows one activation; the passkey signed another: refused (point 21).
func TestASignatureForAnotherActivationIsRefused(t *testing.T) {
	w := newWorld(t)
	s, _ := w.present(t, "plant-a", Edge)
	shown := Activation{Fleet: "fleet-1", Approver: "ann", Items: []Item{item(s, 16, "Joe", "phone")}}
	signedFor := shown
	signedFor.Items = []Item{item(s, 20, "Joe", "phone")}
	st := registry.Statement{Kind: "activate", Fleet: "fleet-1", Registry: w.reg.Version, Body: signedFor.Hash(), Expires: t0.Add(time.Hour), Nonce: "n"}
	if _, err := Activate(rp, w.reg, w.slots, shown, st, w.ann.sign(st), t0.Add(2*time.Minute)); err == nil {
		t.Fatal("a signature over another activation was taken")
	}
}

func TestSlotsAreCapped(t *testing.T) {
	var open []Slot
	for i := range MaxOpenPerUser {
		s, _, err := Open("f", "https://f/e", pin, anc, "e-"+string(rune('a'+i)), Edge, "basic", "ann", open, t0)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, s)
	}
	if _, _, err := Open("f", "https://f/e", pin, anc, "one-more", Edge, "basic", "ann", open, t0); err == nil {
		t.Fatal("an operator opened more than the cap")
	}
	if _, _, err := Open("f", "https://f/e", pin, anc, "one-more", Edge, "basic", "bob", open, t0); err != nil {
		t.Fatalf("another operator was capped by ann's slots: %v", err)
	}
}

// Someone who learned the slot's stored commitment (a read of the fleet's data) signs it with their own key but does
// not hold the code: the secret itself is checked, not only the signature over its hash.
func TestTheCommitmentAloneDoesNotAdmit(t *testing.T) {
	s, code, _ := Open("fleet-1", "https://fleet.example/enrol", pin, anc, "plant-a", Edge, "basic", "opener", nil, t0)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	p := Present(code, attacker) // signs the right commitment ...
	p.Secret = "not-the-code"    // ... but sends a secret it does not have
	if _, err := Accept("fleet-1", s, p, t0); err == nil {
		t.Fatal("a presentation without the code's secret was taken")
	}
}

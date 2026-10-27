// SPDX-License-Identifier: EUPL-1.2

package registry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var (
	t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	rp = RP{ID: "fleet.example", Origin: "https://fleet.example"}
)

// authenticator is a test passkey: it signs assertions as a browser and an authenticator would.
type authenticator struct {
	id     string
	alg    string // es256, eddsa, rs256
	ec     *ecdsa.PrivateKey
	ed     ed25519.PrivateKey
	rsa    *rsa.PrivateKey
	synced bool // reports backup eligible and backed up (a synced passkey)
}

func newAuth(t *testing.T, id, alg string, synced bool) *authenticator {
	a := &authenticator{id: id, alg: alg, synced: synced}
	switch alg {
	case "es256":
		a.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "eddsa":
		_, a.ed, _ = ed25519.GenerateKey(rand.Reader)
	case "rs256":
		a.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	return a
}

func (a *authenticator) cose(t *testing.T) string {
	var m map[int]any
	switch a.alg {
	case "es256":
		raw, _ := a.ec.PublicKey.Bytes() // 0x04 | x | y
		m = map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:]}
	case "eddsa":
		m = map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(a.ed.Public().(ed25519.PublicKey))}
	case "rs256":
		m = map[int]any{1: 3, 3: -257, -1: a.rsa.N.Bytes(), -2: []byte{1, 0, 1}}
	}
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *authenticator) officer(t *testing.T) Officer {
	return Officer{ID: a.id, Name: a.id, CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred-" + a.id)),
		PublicKey: a.cose(t), DeviceBound: !a.synced}
}

type tweak struct {
	typ, origin, rpID string
	flags             byte
	challenge         []byte
	crossOrigin       bool
}

func (a *authenticator) sign(t *testing.T, st Statement, tw tweak) Signature {
	typ, origin, rpID := "webauthn.get", rp.Origin, rp.ID
	if tw.typ != "" {
		typ = tw.typ
	}
	if tw.origin != "" {
		origin = tw.origin
	}
	if tw.rpID != "" {
		rpID = tw.rpID
	}
	ch := st.Challenge()
	if tw.challenge != nil {
		ch = tw.challenge
	}
	cdj, _ := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(ch), "origin": origin,
		"crossOrigin": tw.crossOrigin})
	flags := byte(flagUP | flagUV)
	if a.synced {
		flags |= flagBE | flagBS
	}
	if tw.flags != 0 {
		flags = tw.flags
	}
	h := sha256.Sum256([]byte(rpID))
	ad := append(append(h[:], flags), 0, 0, 0, 7)
	ch2 := sha256.Sum256(cdj)
	msg := append(append([]byte{}, ad...), ch2[:]...)
	var sig []byte
	switch a.alg {
	case "es256":
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, a.ec, d[:])
	case "eddsa":
		sig = ed25519.Sign(a.ed, msg)
	case "rs256":
		d := sha256.Sum256(msg)
		sig, _ = rsa.SignPKCS1v15(rand.Reader, a.rsa, crypto.SHA256, d[:])
	}
	enc := base64.RawURLEncoding.EncodeToString
	return Signature{Officer: a.id, ClientDataJSON: enc(cdj), AuthenticatorData: enc(ad), Sig: enc(sig)}
}

func stmt(r Registry, under int64) Statement {
	return Statement{Kind: "registry", Fleet: r.Fleet, Registry: under, Body: r.Hash(), Expires: t0.Add(time.Hour), Nonce: "n1"}
}

func TestAnAssertionVerifiesOnlyAsSigned(t *testing.T) {
	for _, alg := range []string{"es256", "eddsa", "rs256"} {
		a := newAuth(t, "ann", alg, false)
		st := Statement{Kind: "activate", Fleet: "f", Registry: 1, Body: "ab", Expires: t0.Add(time.Hour), Nonce: "x"}
		if synced, err := rp.Verify(a.sign(t, st, tweak{}), a.officer(t), st, t0); err != nil || synced {
			t.Fatalf("%s: a good assertion: synced %v, %v", alg, synced, err)
		}
		other := st
		other.Body = "cd" // the page showed one statement, the passkey signed another
		for name, c := range map[string]struct {
			sig Signature
			st  Statement
			at  time.Time
		}{
			"another statement":       {a.sign(t, st, tweak{}), other, t0},
			"another origin":          {a.sign(t, st, tweak{origin: "https://evil.example"}), st, t0},
			"another relying party":   {a.sign(t, st, tweak{rpID: "id.example"}), st, t0},
			"a registration ceremony": {a.sign(t, st, tweak{typ: "webauthn.create"}), st, t0},
			"cross-origin":            {a.sign(t, st, tweak{crossOrigin: true}), st, t0},
			"no user verification":    {a.sign(t, st, tweak{flags: flagUP}), st, t0},
			"expired":                 {a.sign(t, st, tweak{}), st, t0.Add(2 * time.Hour)},
			"another key":             {newAuth(t, "ann", alg, false).sign(t, st, tweak{}), st, t0},
		} {
			if _, err := rp.Verify(c.sig, a.officer(t), c.st, c.at); err == nil {
				t.Errorf("%s: %s: accepted", alg, name)
			}
		}
	}
	s := newAuth(t, "syd", "es256", true)
	st := Statement{Kind: "activate", Fleet: "f", Registry: 1, Body: "ab", Expires: t0.Add(time.Hour), Nonce: "x"}
	if synced, err := rp.Verify(s.sign(t, st, tweak{}), s.officer(t), st, t0); err != nil || !synced {
		t.Fatalf("a synced passkey not reported as synced: %v %v", synced, err)
	}
}

// fleet: officers, the anchor, and helpers to propose the next version.
type fleet struct {
	t     *testing.T
	auths map[string]*authenticator
	cur   Registry
}

func newFleet(t *testing.T, ids ...string) *fleet {
	f := &fleet{t: t, auths: map[string]*authenticator{}}
	for _, id := range ids {
		f.auths[id] = newAuth(t, id, "es256", strings.HasPrefix(id, "synced-"))
	}
	r := Registry{Fleet: "fleet-1", Version: 1}
	for _, id := range ids {
		r.Officers = append(r.Officers, f.auths[id].officer(t))
	}
	c := Change{Registry: r, Statement: stmt(r, 1)}
	for _, id := range ids {
		c.Signatures = append(c.Signatures, f.auths[id].sign(t, c.Statement, tweak{}))
	}
	acc, err := Anchor(rp, c, t0)
	if err != nil {
		t.Fatal(err)
	}
	f.cur = acc.Registry
	return f
}

// next proposes a registry with these officers, signed by these ids (new ids get a new passkey).
func (f *fleet) next(officers []string, signers ...string) Change {
	r := Registry{Fleet: f.cur.Fleet, Version: f.cur.Version + 1, Previous: f.cur.Hash()}
	for _, id := range officers {
		if f.auths[id] == nil {
			f.auths[id] = newAuth(f.t, id, "es256", strings.HasPrefix(id, "synced-"))
		}
		r.Officers = append(r.Officers, f.auths[id].officer(f.t))
	}
	c := Change{Registry: r, Statement: stmt(r, f.cur.Version)}
	for _, id := range signers {
		c.Signatures = append(c.Signatures, f.auths[id].sign(f.t, c.Statement, tweak{}))
	}
	return c
}

func TestTheAnchorNeedsEveryOfficersOwnSignature(t *testing.T) {
	newFleet(t, "ann", "bob", "cat") // succeeds
	a, b := newAuth(t, "ann", "es256", false), newAuth(t, "bob", "es256", false)
	c3 := newAuth(t, "cat", "es256", false)
	r := Registry{Fleet: "f", Version: 1, Officers: []Officer{a.officer(t), b.officer(t), c3.officer(t)}}
	ch := Change{Registry: r, Statement: stmt(r, 1)}
	ch.Signatures = []Signature{a.sign(t, ch.Statement, tweak{}), b.sign(t, ch.Statement, tweak{})}
	if _, err := Anchor(rp, ch, t0); err == nil || !strings.Contains(err.Error(), "cat") {
		t.Fatalf("an anchor one officer did not sign: %v", err)
	}
	two := Registry{Fleet: "f", Version: 1, Officers: []Officer{a.officer(t), b.officer(t)}}
	ch2 := Change{Registry: two, Statement: stmt(two, 1)}
	ch2.Signatures = []Signature{a.sign(t, ch2.Statement, tweak{}), b.sign(t, ch2.Statement, tweak{})}
	if _, err := Anchor(rp, ch2, t0); err == nil {
		t.Fatal("an anchor with two officers")
	}
}

func TestRegistryChanges(t *testing.T) {
	cases := []struct {
		name     string
		officers []string
		signers  []string
		mutate   func(f *fleet, c *Change)
		ok       bool
		now      bool // effective at once (break-glass)
	}{
		{name: "add an officer: two signatures, one device-bound, the newcomer's own", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam", "eve"}, signers: []string{"ann", "synced-sue", "eve"}, ok: true},
		{name: "only synced passkeys", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam", "eve"}, signers: []string{"synced-sue", "synced-sam", "eve"}},
		{name: "one signature", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam", "eve"}, signers: []string{"ann", "eve"}},
		{name: "the newcomer has not signed", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam", "eve"}, signers: []string{"ann", "bob"}},
		{name: "remove one with two of five (no majority)", officers: []string{"ann", "bob", "synced-sue", "synced-sam"}, signers: []string{"ann", "bob"}},
		{name: "remove one with three of five", officers: []string{"ann", "bob", "synced-sue", "synced-sam"}, signers: []string{"ann", "bob", "cat"}, ok: true},
		{name: "fewer than three after", officers: []string{"ann", "bob"}, signers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam"}},
		{name: "one officer signing twice", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam", "eve"}, signers: []string{"ann", "ann", "eve"}},
		{name: "a version skipped", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam"}, signers: []string{"ann", "bob"},
			mutate: func(f *fleet, c *Change) { c.Registry.Version++ }},
		{name: "another previous", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam"}, signers: []string{"ann", "bob"},
			mutate: func(f *fleet, c *Change) { c.Registry.Previous = strings.Repeat("0", 64) }},
		{name: "break-glass by a majority with a device-bound passkey", officers: []string{"ann", "bob", "cat", "synced-sue"}, signers: []string{"ann", "bob", "cat"},
			mutate: func(f *fleet, c *Change) { c.BreakGlass = true }, ok: true, now: true},
		{name: "break-glass by two of five", officers: []string{"ann", "bob", "cat", "synced-sue", "synced-sam", "eve"}, signers: []string{"ann", "bob", "eve"},
			mutate: func(f *fleet, c *Change) { c.BreakGlass = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFleet(t, "ann", "bob", "cat", "synced-sue", "synced-sam") // five officers, two with synced passkeys
			ch := f.next(c.officers, c.signers...)
			if c.mutate != nil {
				c.mutate(f, &ch)
				ch.Statement = stmt(ch.Registry, f.cur.Version) // signed after the change: only the rule refuses it
				ch.Signatures = nil
				for _, id := range c.signers {
					ch.Signatures = append(ch.Signatures, f.auths[id].sign(t, ch.Statement, tweak{}))
				}
			}
			acc, err := Apply(rp, f.cur, ch, t0)
			if (err == nil) != c.ok {
				t.Fatalf("ok = %v, want %v (%v)", err == nil, c.ok, err)
			}
			if err == nil {
				if want := map[bool]time.Time{true: t0, false: t0.Add(ChangeDelay)}[c.now]; !acc.Effective.Equal(want) || acc.BreakGlass != c.now {
					t.Fatalf("effective %v (break-glass %v), want %v", acc.Effective, acc.BreakGlass, want)
				}
			}
		})
	}
}

func TestAStatementForAnotherRegistryIsRefused(t *testing.T) {
	f := newFleet(t, "ann", "bob", "cat")
	ch := f.next([]string{"ann", "bob", "cat", "dan"}, "ann", "bob", "dan")
	ch.Statement.Body = strings.Repeat("a", 64) // signed for something else
	ch.Signatures = []Signature{f.auths["ann"].sign(t, ch.Statement, tweak{}), f.auths["bob"].sign(t, ch.Statement, tweak{}), f.auths["dan"].sign(t, ch.Statement, tweak{})}
	if _, err := Apply(rp, f.cur, ch, t0); err == nil {
		t.Fatal("a statement approving another registry was taken")
	}
	ok := f.next([]string{"ann", "bob", "cat", "dan"}, "ann", "bob", "dan")
	acc, err := Apply(rp, f.cur, ok, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(rp, acc.Registry, ok, t0); err == nil { // the same change again: an older version cannot come back
		t.Fatal("a replayed change was taken")
	}
}

// One person's two signatures are refused as such, not merely counted once (two signatures come from two people).
func TestOneOfficerSigningTwiceIsNamed(t *testing.T) {
	f := newFleet(t, "ann", "bob", "cat")
	ch := f.next([]string{"ann", "bob", "cat"}, "ann", "ann")
	if _, err := Apply(rp, f.cur, ch, t0); err == nil || !strings.Contains(err.Error(), "signed twice") {
		t.Fatalf("got %v", err)
	}
}

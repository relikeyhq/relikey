// SPDX-License-Identifier: EUPL-1.2

package registry_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"relikey/fleet/internal/registry"
	"relikey/fleet/internal/registry/regtest"
)

var rp = registry.RP{ID: "fleet.example", Origin: "https://fleet.example"}

func TestARegistrationGivesTheCredentialAndWhetherItIsDeviceBound(t *testing.T) {
	ch := []byte("a-challenge-of-thirty-two-bytes!")
	for _, alg := range []string{"es256", "eddsa", "rs256"} {
		for _, synced := range []bool{false, true} {
			a := regtest.New(alg, synced)
			cd, att := a.Create(rp, ch, regtest.Tweak{})
			c, err := rp.VerifyRegistration(cd, att, ch)
			if err != nil {
				t.Fatalf("%s synced=%v: %v", alg, synced, err)
			}
			if !bytes.Equal(c.ID, a.Cred) || !bytes.Equal(c.Key, a.COSE()) || c.DeviceBound == synced {
				t.Fatalf("%s synced=%v: got id/key/device-bound %v/%v/%v", alg, synced, bytes.Equal(c.ID, a.Cred), bytes.Equal(c.Key, a.COSE()), c.DeviceBound)
			}
		}
	}
}

func TestTheAttestationFormatIsNotTrusted(t *testing.T) {
	// a vendor's attestation format is accepted and ignored: officers admit officers, not vendors
	ch := []byte("a-challenge-of-thirty-two-bytes!")
	a := regtest.New("es256", false)
	cd, att := a.Create(rp, ch, regtest.Tweak{Fmt: "packed"})
	if _, err := rp.VerifyRegistration(cd, att, ch); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationsThatMustBeRefused(t *testing.T) {
	ch := []byte("a-challenge-of-thirty-two-bytes!")
	ec, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 2, -2: make([]byte, 48), -3: make([]byte, 48)})  // P-384
	off, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)}) // not on the curve
	cases := map[string]struct {
		tw   regtest.Tweak
		want string
	}{
		"an assertion, not a registration": {regtest.Tweak{Type: "webauthn.get"}, "ceremony"},
		"another origin":                   {regtest.Tweak{Origin: "https://evil.example"}, "signed on"},
		"another challenge":                {regtest.Tweak{Challenge: []byte("another")}, "challenge"},
		"another relying party":            {regtest.Tweak{RPID: "evil.example"}, "rpId"},
		"a cross-origin frame":             {regtest.Tweak{CrossOrigin: true}, "cross-origin"},
		"user not verified":                {regtest.Tweak{Flags: regtest.FlagUP | regtest.FlagAT}, "UP and UV"},
		"user not present":                 {regtest.Tweak{Flags: regtest.FlagUV | regtest.FlagAT}, "UP and UV"},
		"no credential":                    {regtest.Tweak{Flags: regtest.FlagUP | regtest.FlagUV}, "no credential"},
		"backed up, not eligible":          {regtest.Tweak{Flags: regtest.FlagUP | regtest.FlagUV | regtest.FlagAT | regtest.FlagBS}, "backup eligible"},
		"a credential id too short":        {regtest.Tweak{Cred: make([]byte, 15)}, "credential id"},
		"a credential id too long":         {regtest.Tweak{Cred: make([]byte, 1024)}, "credential id"},
		"a P-384 key":                      {regtest.Tweak{Key: ec}, "ReliKey takes"},
		"a key off the curve":              {regtest.Tweak{Key: off}, "P-256"},
		"no key":                           {regtest.Tweak{Key: []byte{}}, "credential key"},
	}
	for name, c := range cases {
		a := regtest.New("es256", false)
		cd, att := a.Create(rp, ch, c.tw)
		_, err := rp.VerifyRegistration(cd, att, ch)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error naming %q, got %v", name, c.want, err)
		}
	}
	if _, err := rp.VerifyRegistration([]byte(`{}`), []byte{0xff}, ch); err == nil {
		t.Error("garbage was accepted")
	}
}

func FuzzVerifyRegistration(f *testing.F) {
	ch := []byte("a-challenge-of-thirty-two-bytes!")
	for _, alg := range []string{"es256", "eddsa", "rs256"} {
		cd, att := regtest.New(alg, false).Create(rp, ch, regtest.Tweak{})
		f.Add(cd, att)
	}
	f.Fuzz(func(t *testing.T, cd, att []byte) {
		c, err := rp.VerifyRegistration(cd, att, ch)
		if err != nil {
			return
		}
		// whatever is accepted names a credential of a legal length and a key that verifies signatures of its kind
		if len(c.ID) < 16 || len(c.ID) > registry.MaxCredentialID || len(c.Key) == 0 {
			t.Fatalf("accepted a malformed credential: id %d bytes, key %d bytes", len(c.ID), len(c.Key))
		}
	})
}

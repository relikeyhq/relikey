// SPDX-License-Identifier: EUPL-1.2

package enrol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

// Whatever the installer is handed, the parser never panics, and what it accepts survives a round trip.
func FuzzParseCode(f *testing.F) {
	_, good, _ := Open("fleet-1", "https://fleet.example/enrol", pin, anc, "plant-a", Edge, "basic", "ann", nil, t0)
	f.Add(good.String())
	f.Add(CodePrefix)
	f.Add(CodePrefix + "e30")
	f.Add("relikey-enrol-v1:" + strings.Repeat("A", 300))
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCode(s)
		if err != nil {
			return
		}
		again, err := ParseCode(c.String())
		if err != nil || again != c {
			t.Fatalf("a parsed code does not survive a round trip: %+v", c)
		}
	})
}

// A presentation is taken only with the slot's own secret and a signature by the presented key.
func FuzzAccept(f *testing.F) {
	s, code, _ := Open("fleet-1", "https://fleet.example/enrol", pin, anc, "plant-a", Edge, "basic", "ann", nil, t0)
	seed := sha256.Sum256([]byte("edge"))
	good := Present(code, ed25519.NewKeyFromSeed(seed[:]))
	f.Add(good.Slot, good.Key, good.Secret, good.Sig)
	f.Add(good.Slot, good.Key, "guess", good.Sig)
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, slot, key, secret, sig string) {
		got, err := Accept("fleet-1", s, Presentation{Slot: slot, Key: key, Secret: secret, Sig: sig}, t0)
		if err == nil && (secret != code.Secret || got.Key != key) {
			t.Fatalf("taken without the slot's secret: secret %q", secret)
		}
	})
}

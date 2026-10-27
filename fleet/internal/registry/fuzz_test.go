// SPDX-License-Identifier: EUPL-1.2

package registry

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// Random authenticator data never panics the parser.
func FuzzParseAuthData(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x41}, 37))
	f.Add(append(bytes.Repeat([]byte{0}, 32), 0x45, 0, 0, 0, 1, 0, 0))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseAuthData(raw, "fleet.example")
	})
}

// Random keys and signatures never verify, and never panic.
func FuzzVerifyCOSE(f *testing.F) {
	f.Add([]byte{0xa0}, []byte{0x30, 0x06})
	f.Add([]byte{0xa5, 0x01, 0x02, 0x03, 0x26}, []byte{})
	f.Fuzz(func(t *testing.T, key, sig []byte) {
		if err := verifyCOSE(key, []byte("the signed bytes"), sig); err == nil {
			t.Fatalf("a random key and signature verified: key %x sig %x", key, sig)
		}
	})
}

// Any change to a signed assertion is refused: what verifies is exactly what the passkey signed.
func FuzzAssertionMutation(f *testing.F) {
	a := newAuth(&testing.T{}, "ann", "es256", false)
	st := Statement{Kind: "activate", Fleet: "f", Registry: 1, Body: "ab", Expires: t0.Add(1 << 40), Nonce: "x"}
	good := a.sign(&testing.T{}, st, tweak{})
	o := a.officer(&testing.T{})
	cdj, _ := base64.RawURLEncoding.DecodeString(good.ClientDataJSON)
	ad, _ := base64.RawURLEncoding.DecodeString(good.AuthenticatorData)
	f.Add(cdj, ad, uint8(0), uint8(0))
	f.Add(cdj, ad, uint8(5), uint8(1))
	f.Fuzz(func(t *testing.T, c, d []byte, pos, bit uint8) {
		if len(c) > 0 {
			c = bytes.Clone(c)
			c[int(pos)%len(c)] ^= 1 << (bit % 8)
		}
		s := good
		s.ClientDataJSON = base64.RawURLEncoding.EncodeToString(c)
		s.AuthenticatorData = base64.RawURLEncoding.EncodeToString(d)
		if _, err := rp.Verify(s, o, st, t0); err == nil && (!bytes.Equal(c, cdj) || !bytes.Equal(d, ad)) {
			t.Fatalf("a changed assertion verified: client data %q", c)
		}
	})
}

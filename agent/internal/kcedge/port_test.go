// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Guards of KeyClerk 0.23.0 that its conformance set does not exercise yet; each of
// these tests fails when its guard is removed (mutants.py).

func testKey(seed byte) (ed25519.PrivateKey, string) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	k := ed25519.NewKeyFromSeed(s)
	return k, hex.EncodeToString(k.Public().(ed25519.PublicKey))
}

func seal(t *testing.T, k ed25519.PrivateKey, pub string, obj Object, format string) Object {
	t.Helper()
	body := Object{"format": format, "key_id": KeyID(pub)}
	for kk, v := range obj {
		body[kk] = v
	}
	raw := Encode(body)
	return Object{"bytes": base64.StdEncoding.EncodeToString(raw), "signature": hex.EncodeToString(ed25519.Sign(k, raw)),
		"key": pub, "key_id": KeyID(pub)}
}

func TestASealedObjectWithAnExtraMemberIsRefused(t *testing.T) {
	k, pub := testKey(7)
	s := seal(t, k, pub, Object{"edge": "edge-a"}, EndedFormat)
	if _, _, err := UnsealValue(s, pub, EndedFormat); err != nil {
		t.Fatalf("the plain sealed object is refused: %v", err)
	}
	s["note"] = "an extra member"
	if _, _, err := UnsealValue(s, pub, EndedFormat); err == nil || !strings.Contains(err.Error(), "exactly") {
		t.Fatalf("an extra member is accepted (%v)", err)
	}
}

func TestSignedBytesWithALineBreakInTheirBase64AreRefused(t *testing.T) {
	k, pub := testKey(7)
	s := seal(t, k, pub, Object{"edge": "edge-a", "reason": "a long enough reason to split the base64"}, EndedFormat)
	b64 := s["bytes"].(string)
	s["bytes"] = b64[:8] + "\n" + b64[8:] // Go's decoder skips \n even in strict mode; KeyClerk refuses it
	if _, _, err := UnsealValue(s, pub, EndedFormat); err == nil {
		t.Fatal("base64 with a line break is accepted")
	}
}

// FuzzNewParsers: the 0.23.0 parsers never panic on arbitrary JSON and arbitrary key text.
func FuzzNewParsers(f *testing.F) {
	f.Add([]byte(`{"bytes":"e30=","signatures":[{"key":"00","key_id":"00","signature":"00"}]}`), "BCGq5Q3VnMjl")
	f.Add([]byte(`{"bytes":"e30=","signature":"","key":"","key_id":""}`), "")
	f.Fuzz(func(t *testing.T, in []byte, key string) {
		if v, err := Parse(in); err == nil {
			_, _ = UnsealMulti(v, []string{key}, OfficerFormat)
			_, _, _ = UnsealValue(v, key, CeilingFormat)
			_, _ = CheckCeiling("edge-a", key, v, 0)
		}
		_, _ = LoadUnlockPublic(key)
		_, _ = UnlockPrivate(key)
		_ = VerifyModule(in, key)
	})
}

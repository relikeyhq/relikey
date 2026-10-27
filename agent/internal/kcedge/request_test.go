// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
	"testing"
)

// TestSignedRequestsMatchKeyClerk: testdata/requests.json holds headers signed by
// keyclerk.edge.sign_request with seed key 5; Ed25519 is deterministic, so the
// headers must be equal byte for byte.
func TestSignedRequestsMatchKeyClerk(t *testing.T) {
	var set struct {
		Source    string `json:"source"`
		Edge      string `json:"edge"`
		Seed      byte   `json:"seed"`
		Seconds   int64  `json:"seconds"`
		Nonce     string `json:"nonce"`
		PublicKey string `json:"public_key"`
		Cases     []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Body   string `json:"body"`
			Header string `json:"header"`
		} `json:"cases"`
	}
	load(t, "requests.json", &set)
	if set.Source != "keyclerk.edge.sign_request" || len(set.Cases) == 0 {
		t.Fatal("requests.json must be generated from keyclerk.edge.sign_request")
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = set.Seed
	}
	key := ed25519.NewKeyFromSeed(seed)
	if pub, _ := PublicKey(set.PublicKey); !pub.Equal(key.Public()) {
		t.Fatal("seed and public key disagree")
	}
	for _, c := range set.Cases {
		body, _ := base64.StdEncoding.DecodeString(c.Body)
		if got := SignRequest(key, set.Edge, c.Method, c.Path, body, set.Seconds, set.Nonce); got != c.Header {
			t.Errorf("%s %s:\n got %s\nwant %s", c.Method, c.Path, got, c.Header)
		}
	}
}

// TestRequestVectorsFromTheConformanceSet: KeyClerk's "requests" family (decision 0026, edge protocol 1.2). The bytes
// this side signs must be the desk's for every case, accepted or refused; for an accepted case the header must be the
// desk's byte for byte (Ed25519 is deterministic). The refused cases change the request after signing, so their
// headers do not verify over the message the desk builds.
func TestRequestVectorsFromTheConformanceSet(t *testing.T) {
	var set struct {
		Requests struct {
			Cases []struct {
				Name      string `json:"name"`
				Edge      string `json:"edge"`
				Method    string `json:"method"`
				Path      string `json:"path"`
				Body      string `json:"body"`
				Seconds   int64  `json:"seconds"`
				Nonce     string `json:"nonce"`
				Header    string `json:"header"`
				PublicKey string `json:"public_key"`
				Now       int64  `json:"now"`
				Expected  struct {
					Message string `json:"message"`
					OK      bool   `json:"ok"`
				} `json:"expected"`
			} `json:"cases"`
		} `json:"requests"`
	}
	load(t, "edge.json", &set)
	if len(set.Requests.Cases) == 0 {
		t.Fatal("no requests family in edge.json")
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	key := ed25519.NewKeyFromSeed(seed)
	for _, c := range set.Requests.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, _ := base64.StdEncoding.DecodeString(c.Body)
			want, _ := base64.StdEncoding.DecodeString(c.Expected.Message)
			if got := RequestMessage(c.Edge, c.Method, c.Path, c.Seconds, c.Nonce, body); string(got) != string(want) {
				t.Fatalf("message:\n got %q\nwant %q", got, want)
			}
			if c.Expected.OK {
				if pub, _ := PublicKey(c.PublicKey); !pub.Equal(key.Public()) {
					t.Fatal("the accepted case is not signed with seed 7")
				}
				if got := SignRequest(key, c.Edge, c.Method, c.Path, body, c.Seconds, c.Nonce); got != c.Header {
					t.Fatalf("header:\n got %s\nwant %s", got, c.Header)
				}
			}
		})
	}
}

func TestNewNonceIsWhatTheDeskAccepts(t *testing.T) {
	ok := regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	seen := map[string]bool{}
	for range 1000 {
		n := NewNonce()
		if !ok.MatchString(n) || seen[n] {
			t.Fatalf("nonce %q", n)
		}
		seen[n] = true
	}
}

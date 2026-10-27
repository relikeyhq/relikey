// SPDX-License-Identifier: EUPL-1.2

package httpx

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// server is a TLS test server offering only the given groups; nil offers Go's defaults (hybrid first).
func server(t *testing.T, groups []tls.CurveID) (url, pin string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{CurvePreferences: groups}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

func TestAHybridLinkNegotiatesAndRecordsTheGroup(t *testing.T) {
	url, pin := server(t, nil)
	g := &Group{}
	c, err := New(Options{Timeout: 5 * time.Second, PinSHA256: pin, RequireHybrid: true, Group: g})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("a peer offering the hybrid was refused: %v", err)
	}
	resp.Body.Close()
	if g.String() != tls.X25519MLKEM768.String() {
		t.Fatalf("recorded group %q, want %q", g.String(), tls.X25519MLKEM768)
	}
}

func TestAHybridLinkRefusesAClassicalPeer(t *testing.T) {
	url, pin := server(t, []tls.CurveID{tls.X25519, tls.CurveP256})
	c, err := New(Options{Timeout: 5 * time.Second, PinSHA256: pin, RequireHybrid: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(url); err == nil {
		t.Fatal("a peer without the hybrid was served: a required link must fail closed")
	}
}

func TestAnUnpinnedLinkStillRecordsWhatItNegotiated(t *testing.T) {
	url, pin := server(t, []tls.CurveID{tls.X25519})
	g := &Group{}
	c, err := New(Options{Timeout: 5 * time.Second, PinSHA256: pin, Group: g})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if g.String() != tls.X25519.String() {
		t.Fatalf("recorded %q, want X25519 (a visible link reports the classical fallback)", g.String())
	}
}

func TestThePinStillHoldsOnAHybridLink(t *testing.T) {
	url, _ := server(t, nil)
	c, err := New(Options{Timeout: 5 * time.Second, PinSHA256: strings.Repeat("0", 64), RequireHybrid: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(url); err == nil || !strings.Contains(err.Error(), "does not match the pinned one") {
		t.Fatalf("a wrong pin passed on a hybrid link: %v", err)
	}
}

// SPDX-License-Identifier: EUPL-1.2

package fleetproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func key(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{"plant-a": key("plant-a").Public().(ed25519.PublicKey)}
}

func report(seq int64) Report {
	return Report{Edge: "plant-a", Seq: seq, At: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), Serial: 7, Release: "0.27.0",
		Mode: "enforce", Profile: "basic", DriftCodes: []string{}}
}

func TestASignedReportVerifiesAndAForgedOneDoesNot(t *testing.T) {
	good, _ := Sign(key("plant-a"), report(1))
	if r, err := Verify(good, keys()); err != nil || r.Seq != 1 {
		t.Fatalf("a good report refused: %v", err)
	}
	other, _ := Sign(key("intruder"), report(1))
	raw, _ := base64.StdEncoding.DecodeString(good.Report)
	tampered := good
	tampered.Report = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(`"serial":7`), []byte(`"serial":9`), 1))
	for name, s := range map[string]Signed{"another key": other, "tampered bytes": tampered} {
		if _, err := Verify(s, keys()); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The client takes nothing from an answer but its status: 204 is delivered, anything else is not.
func TestTheClientTakesNothingButTheStatus(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ok.Close()
	if err := (&Client{URL: ok.URL, HTTP: ok.Client(), Key: key("plant-a")}).Send(t.Context(), report(1)); err != nil {
		t.Fatalf("204: %v", err)
	}
	chatty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"command":"delete everything"}`))
	}))
	defer chatty.Close()
	if err := (&Client{URL: chatty.URL, HTTP: chatty.Client(), Key: key("plant-a")}).Send(t.Context(), report(2)); err == nil {
		t.Fatal("a 200 with a body was taken as delivered")
	}
}

func TestDriftCodesCarryNoText(t *testing.T) {
	got := DriftCodes([]string{"account rogue is not managed by ReliKey but holds the governed role plc-operators, which only a lease grants: reported, not changed", "something new"})
	if len(got) != 2 || got[0] != "rogue_account" || got[1] != "other" {
		t.Fatalf("codes %v", got)
	}
}

// The report's fields are plain words: a signed report with spoofing text is refused, and the client never sends one.
func TestAReportWithSpoofingTextIsRefused(t *testing.T) {
	r := report(1)
	r.Release = "0.27.0\u202e"
	s, _ := Sign(key("plant-a"), r)
	if _, err := Verify(s, keys()); err == nil {
		t.Fatal("a bidi override in the release was accepted")
	}
	if err := (&Client{URL: "https://127.0.0.1:1", Key: key("plant-a")}).Send(t.Context(), r); err == nil || !strings.Contains(err.Error(), "not sent") {
		t.Fatalf("the client sent a report its service refuses: %v", err)
	}
}

// SPDX-License-Identifier: EUPL-1.2

package fleet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"relikey/agent/pkg/fleetproto"
	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
	"strings"
	"testing"
	"time"

	"relikey/agent/pkg/events"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func key(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{"plant-a": key("plant-a").Public().(ed25519.PublicKey)}
}

func report(seq int64, at time.Time) fleetproto.Report {
	return fleetproto.Report{Edge: "plant-a", Seq: seq, At: at, Release: "dev", Mode: "enforce", Profile: "basic",
		Serial: 7, AppliedSerial: 7, DriftCodes: []string{}}
}

func TestASignedReportVerifiesAndAForgedOneDoesNot(t *testing.T) {
	good, _ := fleetproto.Sign(key("plant-a"), report(1, t0))
	if r, err := fleetproto.Verify(good, keys()); err != nil || r.Seq != 1 {
		t.Fatalf("a good report refused: %v", err)
	}
	other, _ := fleetproto.Sign(key("intruder"), report(1, t0))
	unknown, _ := fleetproto.Sign(key("plant-a"), fleetproto.Report{Edge: "plant-z", Seq: 1, At: t0})
	raw, _ := base64.StdEncoding.DecodeString(good.Report)
	tampered := good
	tampered.Report = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(`"serial":7`), []byte(`"serial":9`), 1))
	for name, s := range map[string]fleetproto.Signed{"another key": other, "an unknown edge": unknown, "tampered bytes": tampered,
		"a bad signature": {Report: good.Report, Signature: "00"}} {
		if _, err := fleetproto.Verify(s, keys()); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestAReplayOrAStrayClockIsRefused(t *testing.T) {
	inv, err := Open(filepath.Join(t.TempDir(), "fleet.json"), []string{"plant-a"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.Accept(report(5, t0), t0); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]fleetproto.Report{"the same sequence": report(5, t0), "a lower sequence": report(4, t0),
		"a time too far ahead": report(6, t0.Add(10*time.Minute)), "a time too far behind": report(6, t0.Add(-10*time.Minute))} {
		if err := inv.Accept(r, t0); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := inv.Accept(report(6, t0.Add(time.Second)), t0); err != nil {
		t.Fatalf("the next report refused: %v", err)
	}
}

func TestSilenceIsRaisedAndClearedOnceAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	inv, _ := Open(path, []string{"plant-a", "plant-b"}, time.Minute)
	prev := map[string]string{}
	inv.Sweep(t0, prev)
	_ = inv.Accept(report(1, t0), t0)
	if got := inv.Sweep(t0.Add(30*time.Second), prev); len(got) != 1 || got[0].To != "ok" {
		t.Fatalf("first report: %v", got)
	}
	if got := inv.Sweep(t0.Add(2*time.Minute), prev); len(got) != 1 || got[0].To != "silent" {
		t.Fatalf("silence not raised: %v", got)
	}
	if got := inv.Sweep(t0.Add(3*time.Minute), prev); len(got) != 0 {
		t.Fatalf("silence raised twice: %v", got)
	}
	_ = inv.Accept(report(2, t0.Add(4*time.Minute)), t0.Add(4*time.Minute))
	if got := inv.Sweep(t0.Add(4*time.Minute), prev); len(got) != 1 || got[0].To != "ok" {
		t.Fatalf("recovery not seen: %v", got)
	}
	for _, e := range inv.View() {
		if e.Edge == "plant-b" && e.State != "unknown" {
			t.Fatalf("an edge that never reported is %q, want unknown (never last-known-good)", e.State)
		}
	}
	again, err := Open(path, []string{"plant-a", "plant-b"}, time.Minute)
	if err != nil || again.edges["plant-a"].Last == nil || again.edges["plant-a"].Last.Seq != 2 {
		t.Fatalf("the inventory did not survive a restart: %v", err)
	}
	if err := again.Accept(report(2, t0.Add(4*time.Minute)), t0.Add(4*time.Minute)); err == nil {
		t.Fatal("a replay accepted after a restart")
	}
}

func TestTheHTTPSide(t *testing.T) {
	inv, _ := Open(filepath.Join(t.TempDir(), "fleet.json"), []string{"plant-a"}, time.Minute)
	var emitted []events.Event
	s := &Server{Inv: inv, Keys: keys(), Now: func() time.Time { return t0 }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Emit: func(e events.Event) { emitted = append(emitted, e) }}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	post := func(sg fleetproto.Signed) int {
		b, _ := json.Marshal(sg)
		resp, err := http.Post(srv.URL+"/fleet/v1/report", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good, _ := fleetproto.Sign(key("plant-a"), report(1, t0))
	if c := post(good); c != http.StatusNoContent {
		t.Fatalf("a good report: %d", c)
	}
	if c := post(good); c != http.StatusForbidden {
		t.Fatalf("a replayed report: %d", c)
	}
	resp, _ := http.Get(srv.URL + "/fleet/v1/edges")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "self-reported") || !strings.Contains(string(b), `"state":"ok"`) {
		t.Fatalf("view: %s", b)
	}
	s.emitTransition(Transition{"plant-a", "ok", "silent"})
	if len(emitted) != 1 || emitted[0].Type != "relikey.edge.silent.v1" || emitted[0].Solution != "relikey-fleet" {
		t.Fatalf("silence event: %+v", emitted)
	}
}

// The fleet service is read-only towards edges (decision 0026 point 9): it serves the report route and the view,
// nothing else, and the client takes nothing from an answer but its status.
func TestTheFleetIsReadOnlyTowardsEdges(t *testing.T) {
	inv, _ := Open(filepath.Join(t.TempDir(), "fleet.json"), []string{"plant-a"}, time.Minute)
	s := &Server{Inv: inv, Keys: keys(), Now: func() time.Time { return t0 }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	for _, probe := range []struct{ method, path string }{
		{"GET", "/fleet/v1/report"}, {"POST", "/fleet/v1/command"}, {"POST", "/fleet/v1/edges"}, {"GET", "/fleet/v1/edges/plant-a/exec"},
	} {
		req, _ := http.NewRequest(probe.method, srv.URL+probe.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s answered %d: the fleet serves only its two routes", probe.method, probe.path, resp.StatusCode)
		}
	}
	c := &fleetproto.Client{URL: srv.URL, HTTP: srv.Client(), Key: key("plant-a")}
	if err := c.Send(t.Context(), report(1, t0)); err != nil {
		t.Fatalf("a good report: %v", err)
	}
	chatty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"command":"delete everything"}`)) // 200 with a body: never taken as anything
	}))
	defer chatty.Close()
	if err := (&fleetproto.Client{URL: chatty.URL, HTTP: chatty.Client(), Key: key("plant-a")}).Send(t.Context(), report(2, t0)); err == nil {
		t.Fatal("a 200 with a body was taken as delivered")
	}
}

func TestAnEdgeRemovedFromTheConfigurationLeavesTheInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	inv, _ := Open(path, []string{"plant-a", "plant-b"}, time.Minute)
	_ = inv.Accept(report(1, t0), t0)
	again, err := Open(path, []string{"plant-b"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range again.View() {
		if e.Edge == "plant-a" {
			t.Fatal("an edge no longer configured is still in the inventory")
		}
	}
}

// An enrolled edge (or its stolen key) cannot put spoofing text on the fleet page: bidi overrides, zero-width or
// control characters, kilobytes of text, or fields outside their forms are refused (GUI red team 2026-10-25, A1).
func TestHostileReportFieldsAreRefused(t *testing.T) {
	for name, change := range map[string]func(*fleetproto.Report){
		"a bidi override in the release": func(r *fleetproto.Report) { r.Release = "0.27.0\u202e" },
		"a 20 KB release":                func(r *fleetproto.Report) { r.Release = strings.Repeat("A", 20000) },
		"a zero-width drift code":        func(r *fleetproto.Report) { r.DriftCodes = []string{"all_clear\u200b"} },
		"markup in a drift code":         func(r *fleetproto.Report) { r.DriftCodes = []string{"<b>"} },
		"too many drift codes":           func(r *fleetproto.Report) { r.DriftCodes = make([]string, 17) },
		"a made-up mode":                 func(r *fleetproto.Report) { r.Mode = "enforce, trusted" },
		"a control character":            func(r *fleetproto.Report) { r.Profile = "\u0000" },
		"negative counts":                func(r *fleetproto.Report) { r.LiveLeases = -1 },
	} {
		r := report(1, t0)
		change(&r)
		sg, _ := fleetproto.Sign(key("plant-a"), r)
		if _, err := fleetproto.Verify(sg, keys()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The fleet's listeners answer loopback names only: a page rebound to 127.0.0.1 in DNS sends its own name (A2).
func TestARequestForAnotherHostIsRefused(t *testing.T) {
	inv, _ := Open(filepath.Join(t.TempDir(), "fleet.json"), []string{"plant-a"}, time.Minute)
	srv := httptest.NewServer((&Server{Inv: inv, Keys: keys(), Now: func() time.Time { return t0 },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer srv.Close()
	for host, want := range map[string]int{"rebind.attacker.example": 421, "127.0.0.1:8093": 200, "localhost": 200, "[::1]:8093": 200} {
		req, _ := http.NewRequest("GET", srv.URL+"/fleet/v1/edges", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %s: %d, want %d", host, resp.StatusCode, want)
		}
	}
}

// An edge presents its key on the enrolment route: taken in once, a second key is a conflict the installer shows,
// a wrong secret is refused without a reason (the reason stays on the slot and in the evidence log).
func TestTheEnrolmentRoute(t *testing.T) {
	st, _ := admin.Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	r := registry.Registry{Fleet: "fleet-1", Version: 1, Officers: []registry.Officer{{ID: "ann"}, {ID: "bob"}, {ID: "cat"}}}
	_ = st.SetAnchor(registry.Accepted{Registry: r, Effective: t0}, registry.Change{Registry: r}, admin.Event{At: t0})
	_, code, err := st.OpenSlot("https://edge.example/fleet/v1/enrol", strings.Repeat("a", 64), "plant-c", enrol.Edge, "basic", admin.Event{Subject: "ann"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := Open(filepath.Join(t.TempDir(), "fleet.json"), []string{"plant-a"}, time.Minute)
	srv := httptest.NewServer((&Server{Inv: inv, Keys: keys(), Now: func() time.Time { return t0 }, Admin: st,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer srv.Close()
	post := func(body any) int {
		b, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+"/fleet/v1/enrol", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)
	wrong := code
	wrong.Secret = "guessed"
	for _, c := range []struct {
		name string
		body any
		want int
	}{
		{"a wrong secret", enrol.Present(wrong, k1), 403},
		{"the right one", enrol.Present(code, k1), 204},
		{"a second key", enrol.Present(code, k2), 409},
		{"not a presentation", "nonsense", 400},
	} {
		if got := post(c.body); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

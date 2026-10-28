// SPDX-License-Identifier: EUPL-1.2

package fleet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relikey/agent/pkg/fleetproto"
	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
	"relikey/fleet/internal/registry/regtest"
)

// enrolRig is a fleet anchored with three officers (software passkeys), enrolment on, served over TLS on loopback.
type enrolRig struct {
	st  *admin.Store
	inv *Inventory
	srv *httptest.Server
	ann *regtest.Authenticator
	pin string
}

var stmtRP = registry.RP{ID: "fleet.example", Origin: "https://fleet.example"}

func newEnrolRig(t *testing.T) *enrolRig {
	t.Helper()
	ann, bob, cat := regtest.New("es256", false), regtest.New("eddsa", true), regtest.New("rs256", false)
	reg := registry.Registry{Fleet: "fleet-1", Version: 1,
		Officers: []registry.Officer{ann.Officer("ann", "ann"), bob.Officer("bob", "bob"), cat.Officer("cat", "cat")}}
	st, err := admin.Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.SetAnchor(registry.Accepted{Registry: reg, Effective: now.Add(-time.Hour)}, registry.Change{Registry: reg},
		admin.Event{At: now}); err != nil {
		t.Fatal(err)
	}
	inv, _ := Open(filepath.Join(t.TempDir(), "fleet.json"), []string{"plant-a"}, time.Minute)
	srv := httptest.NewTLSServer((&Server{Inv: inv, Keys: keys(), Now: time.Now, Admin: st,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return &enrolRig{st: st, inv: inv, srv: srv, ann: ann, pin: hex.EncodeToString(sum[:])}
}

func (g *enrolRig) open(t *testing.T, name string) enrol.Code {
	t.Helper()
	_, code, err := g.st.OpenSlot(g.srv.URL+"/fleet/v1/enrol", g.pin, name, enrol.Edge, "basic", admin.Event{Subject: "ann"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (g *enrolRig) post(t *testing.T, path string, body any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := g.srv.Client().Post(g.srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// approve is the officer's activation of one slot: the whole fingerprint in the statement, its last 16 characters
// typed as read from the edge's screen, who read it and how, signed with ann's passkey.
func (g *enrolRig) approve(slot, keyHex string) error {
	fp := enrol.Fingerprint(keyHex)
	flat := strings.ReplaceAll(fp, " ", "")
	a := enrol.Activation{Fleet: "fleet-1", Approver: "ann", Items: []enrol.Item{{Slot: slot, Fingerprint: fp,
		Typed: flat[len(flat)-16:], ReadBy: "the installer", ReadHow: "phone"}}}
	st := registry.Statement{Kind: "activate", Fleet: "fleet-1", Registry: 1, Body: a.Hash(),
		Expires: time.Now().Add(5 * time.Minute), Nonce: "n-" + slot}
	_, err := g.st.Activate(stmtRP, a, st, g.ann.Sign(stmtRP, "ann", st, regtest.Tweak{}), admin.Event{At: time.Now(), Subject: "ann"}, time.Now())
	return err
}

func (g *enrolRig) report(t *testing.T, edge string, priv ed25519.PrivateKey, seq int64) int {
	t.Helper()
	now := time.Now()
	signed, err := fleetproto.Sign(priv, fleetproto.Report{Edge: edge, Seq: now.UnixMilli() - 1000 + seq, At: now, Release: "dev",
		Mode: "enforce", Profile: "basic", Serial: 1, AppliedSerial: 1, DriftCodes: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return g.post(t, "/fleet/v1/report", signed)
}

func (g *enrolRig) state(edge string) string {
	for _, e := range g.inv.View() {
		if e.Edge == edge {
			return e.State
		}
	}
	return "absent"
}

// An edge enrolled by code reports only once an officer's passkey activated its slot; its name cannot be opened
// again; and a configured edge whose name an activation also enrols under another key is refused, never chosen.
func TestAnEdgeReportsOnlyOnceItsSlotIsActivated(t *testing.T) {
	g := newEnrolRig(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	code := g.open(t, "plant-c")
	if got := g.post(t, "/fleet/v1/enrol", enrol.Present(code, priv)); got != 204 {
		t.Fatalf("presentation: %d, want 204", got)
	}
	if got := g.report(t, "plant-c", priv, 1); got != 403 || g.state("plant-c") != "absent" {
		t.Fatalf("a presented, unapproved edge: report %d, state %s; want 403, absent", got, g.state("plant-c"))
	}
	keyHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := g.approve(code.Slot, keyHex); err != nil {
		t.Fatalf("activation refused: %v", err)
	}
	if got := g.report(t, "plant-c", priv, 2); got != 204 || g.state("plant-c") != "ok" {
		t.Fatalf("an activated edge: report %d, state %s; want 204, ok", got, g.state("plant-c"))
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if got := g.report(t, "plant-c", other, 3); got != 403 {
		t.Fatalf("another key under the enrolled name: %d, want 403", got)
	}
	if _, _, err := g.st.OpenSlot(g.srv.URL, g.pin, "plant-c", enrol.Edge, "basic", admin.Event{Subject: "bob"}, time.Now()); err == nil {
		t.Fatal("a second slot for an enrolled edge opened: that is a rotation, never a new slot")
	}
	// plant-a is configured with its own key; an activation enrolling plant-a under another key takes both out
	if got := g.report(t, "plant-a", key("plant-a"), 4); got != 204 {
		t.Fatalf("the configured edge: %d, want 204", got)
	}
	codeA := g.open(t, "plant-a")
	g.post(t, "/fleet/v1/enrol", enrol.Present(codeA, other))
	if err := g.approve(codeA.Slot, hex.EncodeToString(other.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	if a, b := g.report(t, "plant-a", key("plant-a"), 5), g.report(t, "plant-a", other, 6); a != 403 || b != 403 {
		t.Fatalf("two keys for plant-a: configured %d, enrolled %d; want both 403", a, b)
	}
}

// An activation is refused, and logged, when the passkey is not the approver's or the statement is not the one
// signed; nothing becomes active.
func TestAnActivationNeedsTheApproversPasskeyOverThisStatement(t *testing.T) {
	g := newEnrolRig(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	code := g.open(t, "plant-d")
	g.post(t, "/fleet/v1/enrol", enrol.Present(code, priv))
	keyHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	fp := enrol.Fingerprint(keyHex)
	flat := strings.ReplaceAll(fp, " ", "")
	a := enrol.Activation{Fleet: "fleet-1", Approver: "ann", Items: []enrol.Item{{Slot: code.Slot, Fingerprint: fp,
		Typed: flat[len(flat)-16:], ReadBy: "the installer", ReadHow: "phone"}}}
	st := registry.Statement{Kind: "activate", Fleet: "fleet-1", Registry: 1, Body: a.Hash(), Expires: time.Now().Add(time.Minute), Nonce: "x"}
	other := st
	other.Nonce = "y"
	for name, sig := range map[string]registry.Signature{
		"a stranger's passkey":         regtest.New("es256", false).Sign(stmtRP, "ann", st, regtest.Tweak{}),
		"a signature over another one": g.ann.Sign(stmtRP, "ann", other, regtest.Tweak{}),
	} {
		if _, err := g.st.Activate(stmtRP, a, st, sig, admin.Event{Subject: "ann"}, time.Now()); err == nil {
			t.Errorf("%s: activated", name)
		}
	}
	if len(g.st.Enrolled()) != 0 {
		t.Fatal("a refused activation enrolled an edge")
	}
	if l := g.st.Log(1); len(l) != 1 || l[0].Action != "activate" || !strings.HasPrefix(l[0].Detail, "refused") {
		t.Fatalf("the refusal is not in the evidence log: %+v", l)
	}
}

// The enrolment route takes a capped number of presentations a minute; a slot closes after refused presentations.
func TestTheEnrolmentRouteIsRateLimitedAndASlotClosesAfterRefusals(t *testing.T) {
	g := newEnrolRig(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	code := g.open(t, "plant-e")
	wrong := code
	wrong.Secret = "guessed"
	for range enrol.MaxRefused {
		g.post(t, "/fleet/v1/enrol", enrol.Present(wrong, priv))
	}
	if got := g.post(t, "/fleet/v1/enrol", enrol.Present(code, priv)); got != 403 {
		t.Fatalf("the right code after %d refusals: %d, want 403 (the slot is closed)", enrol.MaxRefused, got)
	}
	got := 0
	for range MaxPresentPerMinute - enrol.MaxRefused - 1 { // the minute's cap, counting the presentations above
		got = g.post(t, "/fleet/v1/enrol", enrol.Present(wrong, priv))
	}
	if got == 429 {
		t.Fatal("throttled within the cap")
	}
	if got = g.post(t, "/fleet/v1/enrol", enrol.Present(wrong, priv)); got != 429 {
		t.Fatalf("past the cap: %d, want 429", got)
	}
}

// The edge installer's own code (deploy/edge/install.py enrol_by_code) takes a slot code, presents the edge's key
// over TLS trusting only the code's pin, and prints the fingerprint; an officer's passkey activates the slot, and the
// edge's signed report is taken in: the edge reaches the fleet as enrolled. A second edge with the same code is told
// the slot is taken. Needs Python with cryptography: RELIKEY_INSTALLER=1 (RELIKEY_PYTHON names the interpreter);
// build.py check sets it when they are there.
func TestAnEdgeInstalledWithACodeReachesTheFleetAsEnrolled(t *testing.T) {
	if os.Getenv("RELIKEY_INSTALLER") == "" {
		t.Skip("set RELIKEY_INSTALLER=1 to run it (Python with cryptography)")
	}
	py := os.Getenv("RELIKEY_PYTHON")
	if py == "" {
		py = "python"
	}
	g := newEnrolRig(t)
	code := g.open(t, "plant-f")
	dir := t.TempDir()
	codeFile, seedFile := filepath.Join(dir, "code"), filepath.Join(dir, "seed")
	_ = os.WriteFile(codeFile, []byte(code.String()+"\n"), 0o600)
	seed := sha256.Sum256([]byte("plant-f's enrolment seed"))
	_ = os.WriteFile(seedFile, []byte(hex.EncodeToString(seed[:])), 0o600)
	installer := filepath.Join("..", "..", "..", "deploy", "edge", "install.py")
	run := func() (string, error) {
		out, err := exec.CommandContext(t.Context(), py, "-P", filepath.Join("testdata", "installer_enrol.py"), installer,
			codeFile, seedFile).CombinedOutput()
		return string(out), err
	}
	out, err := run()
	t.Logf("installer: %s", out)
	if err != nil {
		t.Fatalf("the installer's presentation failed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	keyHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if !strings.Contains(out, enrol.Fingerprint(keyHex)) {
		t.Fatalf("the installer did not print the key's fingerprint %s", enrol.Fingerprint(keyHex))
	}
	if strings.Contains(out, code.Secret) || strings.Contains(out, code.String()) {
		t.Fatal("the installer printed the code or its secret")
	}
	if err := g.approve(code.Slot, keyHex); err != nil {
		t.Fatalf("activation refused: %v", err)
	}
	if got := g.report(t, "plant-f", priv, 1); got != 204 || g.state("plant-f") != "ok" {
		t.Fatalf("the installed edge's report: %d, state %s; want 204, ok", got, g.state("plant-f"))
	}
	other := sha256.Sum256([]byte("an impostor's seed"))
	_ = os.WriteFile(seedFile, []byte(hex.EncodeToString(other[:])), 0o600)
	if out, err = run(); err == nil || !strings.Contains(out, "slot already taken") {
		t.Fatalf("a second key with the same code: %v, %s; want a failure saying the slot is taken", err, out)
	}
}

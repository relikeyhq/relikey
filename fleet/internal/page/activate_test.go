// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry/regtest"
)

// Activation through the page: an edge presented its key; an officer types the fingerprint's characters as read from
// the edge's screen, records who read it and how, and signs with their officer passkey; the slot is then active and
// its key enrolled. A non-officer, a wrong typed check, another passkey and a replayed signature are refused.
func TestActivationThroughThePage(t *testing.T) {
	b, _, srv, browser, st, rp := ceremonyRig(t)
	keys := map[string]*regtest.Authenticator{"ann": regtest.New("es256", false), "bob": regtest.New("eddsa", true), "cat": regtest.New("rs256", false)}
	people := map[string]*regtest.Authenticator{}
	if c, _ := call(t, as(t, b, srv, browser, "ann"), srv, "/activate/begin", srv, "application/json", map[string]any{"items": []any{}}); c != 409 {
		t.Fatalf("an activation began before the anchor: %d, want 409", c)
	}
	for _, n := range []string{"ann", "bob", "cat"} {
		c := as(t, b, srv, browser, n)
		register(t, c, srv, rp, keys[n])
		people[n] = keys[n]
	}
	for _, n := range []string{"ann", "bob", "cat"} {
		if code, out := sign(t, as(t, b, srv, browser, n), srv, rp, keys[n]); code != 200 {
			t.Fatalf("%s signs the anchor: %d %v", n, code, out)
		}
	}
	_, code, err := st.OpenSlot("https://edge.example/fleet/v1/enrol", strings.Repeat("a", 64), "plant-c", enrol.Edge, "basic", admin.Event{Subject: "sub-dan"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, edge, _ := ed25519.GenerateKey(nil)
	if err := st.Present(enrol.Present(code, edge), "192.0.2.7", time.Now()); err != nil {
		t.Fatal(err)
	}
	flat := strings.ReplaceAll(enrol.Fingerprint(hex.EncodeToString(edge.Public().(ed25519.PublicKey))), " ", "")
	item := func(typed string) map[string]any {
		return map[string]any{"items": []map[string]string{{"slot": code.Slot, "typed": typed, "read_by": "the installer", "read_how": "phone"}}}
	}
	ann := as(t, b, srv, browser, "ann")
	if _, body, _ := get(t, ann, srv+"/"); !strings.Contains(body, `id="activate-sign"`) || !strings.Contains(body, "192.0.2.7") {
		t.Fatalf("the officer is not offered the activation, or not the source address: %s", body)
	}
	dan := as(t, b, srv, browser, "dan")
	if _, body, _ := get(t, dan, srv+"/"); strings.Contains(body, `id="activate-sign"`) {
		t.Error("a non-officer is offered the activation")
	}
	if c, _ := call(t, dan, srv, "/activate/begin", srv, "application/json", item(flat[len(flat)-16:])); c != 403 {
		t.Errorf("a non-officer began an activation: %d", c)
	}
	if c, _ := call(t, ann, srv, "/activate/begin", srv, "application/json", item("AAAAAAAAAAAAAAAA")); c != 400 {
		t.Errorf("a typed check not from the fingerprint: %d, want 400 before any passkey", c)
	}
	if c, _ := call(t, ann, srv, "/activate/begin", srv, "https://evil.example", item(flat[len(flat)-16:])); c != 403 && c != 415 {
		t.Errorf("another origin began an activation: %d", c)
	}
	signWith := func(key *regtest.Authenticator) (int, map[string]any) {
		c, o := call(t, ann, srv, "/activate/begin", srv, "application/json", item(flat[len(flat)-16:]))
		if c != 200 {
			t.Fatalf("activate begin: %d %v", c, o)
		}
		cd, ad, sig := key.Get(rp, unb64(t, o["challenge"]), regtest.Tweak{})
		e := base64.RawURLEncoding.EncodeToString
		return call(t, ann, srv, "/activate/sign", srv, "application/json", map[string]string{"client_data_json": e(cd), "authenticator_data": e(ad), "signature": e(sig)})
	}
	if c, _ := signWith(regtest.New("es256", false)); c != 400 || len(st.Enrolled()) != 0 {
		t.Fatalf("another passkey activated: %d, enrolled %v", c, st.Enrolled())
	}
	c, out := signWith(people["ann"])
	if c != 200 || st.Enrolled()["plant-c"] != hex.EncodeToString(edge.Public().(ed25519.PublicKey)) {
		t.Fatalf("ann's activation: %d %v, enrolled %v", c, out, st.Enrolled())
	}
	e := base64.RawURLEncoding.EncodeToString
	if c, _ := call(t, ann, srv, "/activate/sign", srv, "application/json", map[string]string{"client_data_json": e([]byte("{}")), "authenticator_data": "", "signature": ""}); c != 400 {
		t.Errorf("a sign without a begun activation: %d, want 400", c)
	}
}

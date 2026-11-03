// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"relikey/agent/pkg/fleetproto"
	"relikey/fleet/internal/registry/regtest"
)

// A key rotation through the page (#26): an edge handed its new key over; the page lists it with what the desk's
// statement says; an officer types the new key's characters as the desk's record shows them, records who read them
// and how, and signs with their officer passkey; the fleet then holds the new key. A non-officer, characters not of
// the new key, another passkey, and a rotation whose old key the fleet no longer holds are refused.
func TestARotationThroughThePage(t *testing.T) {
	b, p, srv, browser, st, rp := ceremonyRig(t)
	keys := map[string]*regtest.Authenticator{"ann": regtest.New("es256", false), "bob": regtest.New("eddsa", true), "cat": regtest.New("rs256", false)}
	for _, n := range []string{"ann", "bob", "cat"} {
		register(t, as(t, b, srv, browser, n), srv, rp, keys[n])
	}
	for _, n := range []string{"ann", "bob", "cat"} {
		if code, out := sign(t, as(t, b, srv, browser, n), srv, rp, keys[n]); code != 200 {
			t.Fatalf("%s signs the anchor: %d %v", n, code, out)
		}
	}
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	_, newPriv, _ := ed25519.GenerateKey(nil)
	oldKey, newKey := hex.EncodeToString(oldPriv.Public().(ed25519.PublicKey)), hex.EncodeToString(newPriv.Public().(ed25519.PublicKey))
	var mu sync.Mutex
	held := map[string]string{"plant-a": oldKey, "plant-b": strings.Repeat("c", 64)}
	p.Held = func(e string) (string, bool) { mu.Lock(); defer mu.Unlock(); k, ok := held[e]; return k, ok }
	for _, e := range []string{"plant-a", "plant-b"} {
		if err := st.Handover(fleetproto.Handover{Edge: e, OldKey: oldKey, NewKey: newKey, At: time.Now()},
			fleetproto.RotationFacts{Edge: e, Officer: "idp:desk-officer", OfficerKey: strings.Repeat("d", 64), NewKey: newKey},
			"192.0.2.9", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	pending := st.PendingRotations()
	ann := as(t, b, srv, browser, "ann")
	if _, body, _ := get(t, ann, srv+"/"); !strings.Contains(body, `id="rotate-sign"`) || !strings.Contains(body, "idp:desk-officer") ||
		!strings.Contains(body, groups(newKey)) || !strings.Contains(body, "the fleet no longer holds the old key") {
		t.Fatalf("the officer is not shown the rotation, the desk's statement, the new key, or the stale one: %s", body)
	}
	dan := as(t, b, srv, browser, "dan")
	if _, body, _ := get(t, dan, srv+"/"); strings.Contains(body, `id="rotate-sign"`) || !strings.Contains(body, "Key rotations") {
		t.Error("a non-officer is offered the approval, or not shown the rotations")
	}
	begin := func(id, typed string) (int, map[string]any) {
		return call(t, ann, srv, "/rotate/begin", srv, "application/json",
			map[string]string{"rotation": id, "typed": typed, "read_by": "ann", "read_how": "desk record"})
	}
	if c, _ := call(t, dan, srv, "/rotate/begin", srv, "application/json", map[string]string{"rotation": pending[0].ID,
		"typed": newKey[:20], "read_by": "dan", "read_how": "desk record"}); c != 403 {
		t.Errorf("a non-officer began an approval: %d, want 403", c)
	}
	if c, _ := begin(pending[0].ID, oldKey[:20]); c != 400 {
		t.Errorf("characters of the old key: %d, want 400 before any passkey", c)
	}
	if c, _ := begin(pending[0].ID, newKey[:19]); c != 400 {
		t.Errorf("19 characters (76 bits): %d, want 400 before any passkey", c)
	}
	if c, _ := begin(pending[1].ID, newKey[:20]); c != 400 {
		t.Errorf("a rotation whose old key the fleet no longer holds: %d, want 400", c)
	}
	signWith := func(key *regtest.Authenticator) (int, map[string]any) {
		c, o := begin(pending[0].ID, newKey[:20])
		if c != 200 {
			t.Fatalf("rotate begin: %d %v", c, o)
		}
		cd, ad, sig := key.Get(rp, unb64(t, o["challenge"]), regtest.Tweak{})
		e := base64.RawURLEncoding.EncodeToString
		return call(t, ann, srv, "/rotate/sign", srv, "application/json", map[string]string{"client_data_json": e(cd), "authenticator_data": e(ad), "signature": e(sig)})
	}
	if c, _ := signWith(regtest.New("es256", false)); c != 400 || len(st.ApprovedRotations()) != 0 {
		t.Fatalf("another passkey approved: %d", c)
	}
	if c, out := signWith(keys["ann"]); c != 200 || len(st.ApprovedRotations()) != 1 || st.ApprovedRotations()[0].Edge != "plant-a" {
		t.Fatalf("ann's approval: %d %v", c, out)
	}
	e := base64.RawURLEncoding.EncodeToString
	if c, _ := call(t, ann, srv, "/rotate/sign", srv, "application/json", map[string]string{"client_data_json": e([]byte("{}")), "authenticator_data": "", "signature": ""}); c != 400 {
		t.Errorf("a sign without a begun approval: %d, want 400", c)
	}
}

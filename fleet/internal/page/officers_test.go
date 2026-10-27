// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/registry"
	"relikey/fleet/internal/registry/regtest"
)

// as signs a person in to the page in a browser of their own.
func as(t *testing.T, b *broker, srv string, base *http.Client, name string) *http.Client {
	t.Helper()
	b.mu.Lock()
	b.claims = func(c map[string]any) { c["sub"], c["preferred_username"] = "sub-"+name, name }
	b.mu.Unlock()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Transport: base.Transport, Jar: jar}
	if code, _, _ := get(t, c, srv+"/"); code != 200 {
		t.Fatalf("%s did not sign in", name)
	}
	return c
}

// call posts JSON as the page's script does; origin "" leaves the header out.
func call(t *testing.T, c *http.Client, srv, path, origin, ctype string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", srv+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", ctype)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func unb64(t *testing.T, v any) []byte {
	b, err := base64.RawURLEncoding.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ceremonyRig(t *testing.T) (*broker, *Page, string, *http.Client, *admin.Store, registry.RP) {
	b, p, srv, browser := rig(t)
	st, _ := admin.Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	p.Admin = st
	p.Cfg.Officers = []string{"ann", "bob", "cat"}
	return b, p, srv.URL, browser, st, p.rp()
}

func register(t *testing.T, c *http.Client, srv string, rp registry.RP, key *regtest.Authenticator) (int, map[string]any) {
	t.Helper()
	code, o := call(t, c, srv, "/officer/begin", srv, "application/json", map[string]any{})
	if code != 200 {
		t.Fatalf("begin: %d %v", code, o)
	}
	cd, att := key.Create(rp, unb64(t, o["challenge"]), regtest.Tweak{})
	e := base64.RawURLEncoding.EncodeToString
	return call(t, c, srv, "/officer/finish", srv, "application/json", map[string]string{"client_data_json": e(cd), "attestation_object": e(att)})
}

func sign(t *testing.T, c *http.Client, srv string, rp registry.RP, key *regtest.Authenticator) (int, map[string]any) {
	t.Helper()
	code, o := call(t, c, srv, "/anchor/begin", srv, "application/json", map[string]any{})
	if code != 200 {
		t.Fatalf("anchor begin: %d %v", code, o)
	}
	cd, ad, sig := key.Get(rp, unb64(t, o["challenge"]), regtest.Tweak{})
	e := base64.RawURLEncoding.EncodeToString
	return call(t, c, srv, "/anchor/sign", srv, "application/json", map[string]string{"client_data_json": e(cd), "authenticator_data": e(ad), "signature": e(sig)})
}

var scriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// The ceremony through the page: three named officers register and sign; the page then offers enrolment and carries
// no script. The script the page carries is exactly the one its policy allows.
func TestTheAnchorCeremonyThroughThePage(t *testing.T) {
	b, _, srv, browser, st, rp := ceremonyRig(t)
	names := []string{"ann", "bob", "cat"}
	keys := map[string]*regtest.Authenticator{"ann": regtest.New("es256", false), "bob": regtest.New("eddsa", true), "cat": regtest.New("rs256", false)}
	people := map[string]*http.Client{}
	for _, n := range names {
		people[n] = as(t, b, srv, browser, n)
		_, body, h := get(t, people[n], srv+"/")
		m := scriptRE.FindStringSubmatch(body)
		if m == nil || !strings.Contains(body, `id="officer-register"`) {
			t.Fatalf("%s is not offered the registration: %s", n, body)
		}
		sum := sha256.Sum256([]byte(m[1]))
		if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(h.Get("Content-Security-Policy"), "script-src "+want) {
			t.Fatalf("the page's script is not the one its policy allows: %s", h.Get("Content-Security-Policy"))
		}
		if code, out := register(t, people[n], srv, rp, keys[n]); code != 200 || out["device_bound"] != !keys[n].Synced {
			t.Fatalf("%s registers: %d %v", n, code, out)
		}
	}
	_, body, _ := get(t, people["ann"], srv+"/")
	if !strings.Contains(body, `id="anchor-sign"`) || !strings.Contains(body, "fingerprint") || !strings.Contains(body, "synced passkey") {
		t.Fatalf("ann is not offered the anchor to sign: %s", body)
	}
	for i, n := range names {
		code, out := sign(t, people[n], srv, rp, keys[n])
		if code != 200 || out["anchored"] != (i == 2) {
			t.Fatalf("%s signs: %d %v", n, code, out)
		}
	}
	if st.Anchor() == "" {
		t.Fatal("not anchored")
	}
	_, body, _ = get(t, people["bob"], srv+"/")
	if strings.Contains(body, "<script") || !strings.Contains(body, `action="/slots"`) {
		t.Fatalf("after the anchor: a script remains, or enrolment is not offered: %s", body)
	}
	if code, _ := call(t, people["ann"], srv, "/officer/begin", srv, "application/json", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("a registration began after the anchor: %d", code)
	}
}

func TestCeremonyRequestsThatMustBeRefused(t *testing.T) {
	b, p, srv, browser, st, rp := ceremonyRig(t)
	dan := as(t, b, srv, browser, "dan")
	if code, out := call(t, dan, srv, "/officer/begin", srv, "application/json", map[string]any{}); code != 403 || !strings.Contains(out["error"].(string), "not named") {
		t.Errorf("an unnamed operator began a registration: %d %v", code, out)
	}
	if _, body, _ := get(t, dan, srv+"/"); strings.Contains(body, "<button type=\"button\"") || strings.Contains(body, "<script") {
		t.Error("an unnamed operator is offered a passkey step")
	}
	ann := as(t, b, srv, browser, "ann")
	for name, c := range map[string]struct {
		client        *http.Client
		origin, ctype string
		want          int
	}{
		"another origin":    {ann, "https://evil.example", "application/json", 403},
		"no origin":         {ann, "", "application/json", 403},
		"a form":            {ann, srv, "application/x-www-form-urlencoded", 415},
		"a plain-text post": {ann, srv, "text/plain", 415},
		"no session":        {&http.Client{Transport: browser.Transport}, srv, "application/json", 403},
	} {
		if code, _ := call(t, c.client, srv, "/officer/begin", c.origin, c.ctype, map[string]any{}); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	if code, _ := call(t, ann, srv, "/officer/begin", srv, "application/json", map[string]any{"extra": 1}); code != 400 {
		t.Errorf("an unknown field was taken: %d", code)
	}
	// the challenge is used once, and only by the session that asked for it
	key := regtest.New("es256", false)
	code, o := call(t, ann, srv, "/officer/begin", srv, "application/json", map[string]any{})
	if code != 200 {
		t.Fatal(code)
	}
	cd, att := key.Create(rp, unb64(t, o["challenge"]), regtest.Tweak{})
	e := base64.RawURLEncoding.EncodeToString
	answer := map[string]string{"client_data_json": e(cd), "attestation_object": e(att)}
	bob := as(t, b, srv, browser, "bob")
	if code, _ := call(t, bob, srv, "/officer/finish", srv, "application/json", answer); code != 400 {
		t.Errorf("bob finished ann's registration: %d", code)
	}
	if code, _ := call(t, ann, srv, "/officer/finish", srv, "application/json", answer); code != 200 {
		t.Fatalf("ann's own registration: %d", code)
	}
	if code, _ := call(t, ann, srv, "/officer/finish", srv, "application/json", answer); code != 400 {
		t.Errorf("a registration answer was replayed: %d", code)
	}
	// a registration answered after five minutes is refused
	code, o = call(t, ann, srv, "/officer/begin", srv, "application/json", map[string]any{})
	if code != 200 {
		t.Fatalf("begin: %d %v", code, o)
	}
	cd, att = regtest.New("es256", false).Create(rp, unb64(t, o["challenge"]), regtest.Tweak{})
	now := p.Now
	p.Now = func() time.Time { return now().Add(challengeTTL) }
	code, _ = call(t, ann, srv, "/officer/finish", srv, "application/json", map[string]string{"client_data_json": e(cd), "attestation_object": e(att)})
	p.Now = now
	if code != 400 {
		t.Errorf("a registration answered after its challenge expired: %d", code)
	}
	// a registration made for another origin is refused
	code, o = call(t, bob, srv, "/officer/begin", srv, "application/json", map[string]any{})
	if code != 200 {
		t.Fatalf("begin: %d %v", code, o)
	}
	cd, att = regtest.New("es256", false).Create(rp, unb64(t, o["challenge"]), regtest.Tweak{Origin: "https://evil.example"})
	if code, _ := call(t, bob, srv, "/officer/finish", srv, "application/json", map[string]string{"client_data_json": e(cd), "attestation_object": e(att)}); code != 400 {
		t.Errorf("a registration for another origin: %d", code)
	}
	// the anchor cannot be signed before everyone registered, nor by someone it does not name
	if code, out := call(t, ann, srv, "/anchor/begin", srv, "application/json", map[string]any{}); code != 409 {
		t.Errorf("anchor signing began with one officer registered: %d %v", code, out)
	}
	register(t, bob, srv, rp, regtest.New("es256", false))
	cat := as(t, b, srv, browser, "cat")
	catKey := regtest.New("es256", false)
	register(t, cat, srv, rp, catKey)
	// a different account registered under cat's name: cat's page says so and offers no signature
	st.Register(regtest.New("es256", false).Officer("sub-cat", "cat"), admin.Event{}) // already cat's: replaced
	b.mu.Lock()
	b.claims = func(c map[string]any) { c["sub"], c["preferred_username"] = "sub-cat-2", "cat" }
	b.mu.Unlock()
	jar, _ := cookiejar.New(nil)
	cat2 := &http.Client{Transport: browser.Transport, Jar: jar}
	if _, body, _ := get(t, cat2, srv+"/"); !strings.Contains(body, "registered by a different account named cat") || strings.Contains(body, `id="anchor-sign"`) {
		t.Errorf("the second cat account is not warned, or is offered the signature: %s", body)
	}
	b.mu.Lock()
	b.claims = nil
	b.mu.Unlock()
	if code, _ := call(t, dan, srv, "/anchor/begin", srv, "application/json", map[string]any{}); code != 403 {
		t.Errorf("dan began signing the anchor: %d", code)
	}
	// cat's passkey answering for ann is refused: the page takes the officer from the session, not the request
	code, o = call(t, ann, srv, "/anchor/begin", srv, "application/json", map[string]any{})
	if code != 200 {
		t.Fatalf("begin: %d %v", code, o)
	}
	cd2, ad, sig := catKey.Get(rp, unb64(t, o["challenge"]), regtest.Tweak{})
	if code, _ := call(t, ann, srv, "/anchor/sign", srv, "application/json", map[string]string{"client_data_json": e(cd2), "authenticator_data": e(ad), "signature": e(sig)}); code != 400 {
		t.Errorf("cat's passkey signed for ann: %d", code)
	}
	if st.Anchor() != "" || p.Admin.Log(1)[0].Action == "anchored" {
		t.Fatal("anchored by refused requests")
	}
}

// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func contextWithClient(ctx context.Context, c *http.Client) context.Context {
	return WithClient(ctx, c)
}

// broker is a fake OIDC provider: discovery, keys, the authorise redirect and the token endpoint. claims shapes the
// next ID token, so each test can issue a wrong one.
type broker struct {
	*httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	nonce    string
	verifier string
	who      string // the person signing in, from a cookie on the broker (a real browser's test); "" is alice
	claims   func(c map[string]any)
}

func newBroker(t *testing.T) *broker {
	b := &broker{}
	b.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	m := http.NewServeMux()
	b.Server = httptest.NewTLSServer(m)
	m.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": b.URL, "authorization_endpoint": b.URL + "/auth",
			"token_endpoint": b.URL + "/token", "jwks_uri": b.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	m.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &b.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	m.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) { // the operator signs in with a passkey
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "no PKCE", http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.nonce, b.verifier = q.Get("nonce"), q.Get("code_challenge")
		b.who = ""
		if c, err := r.Cookie("who"); err == nil {
			b.who = c.Value
		}
		b.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c1&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	m.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("code_verifier") == "" {
			http.Error(w, "no verifier", http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		c := b.base("alice")
		if b.who != "" {
			c["sub"], c["preferred_username"] = "sub-"+b.who, b.who
		}
		c["nonce"], c["sid"] = b.nonce, "broker-session-1"
		if b.claims != nil {
			b.claims(c)
		}
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "id_token": b.sign(t, c)})
	})
	return b
}

func (b *broker) base(sub string) map[string]any {
	now := time.Now()
	return map[string]any{"iss": b.URL, "aud": "relikey-fleet", "azp": "relikey-fleet", "sub": sub,
		"preferred_username": sub, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"resource_access": map[string]any{"relikey-fleet": map[string]any{"roles": []string{"fleet-operator"}}}}
}

func (b *broker) sign(t *testing.T, c map[string]any) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: b.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	o, err := s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := o.CompactSerialize()
	return out
}

// rig: the broker, the page behind a TLS test server (the __Host- cookies need https), and a browser with cookies.
func rig(t *testing.T) (*broker, *Page, *httptest.Server, *http.Client) {
	b := newBroker(t)
	t.Cleanup(b.Close)
	ctx := t.Context()
	var pageSrv *httptest.Server
	mux := http.NewServeMux()
	pageSrv = httptest.NewTLSServer(mux)
	t.Cleanup(pageSrv.Close)
	cfg := Config{Issuer: b.URL, ClientID: "relikey-fleet", RedirectURL: pageSrv.URL + "/callback", Role: "fleet-operator"}
	ctx = contextWithClient(ctx, b.Client())
	p, err := New(ctx, cfg, "s3cret", func() (string, any) {
		return "self-reported, not attested", []map[string]any{{"edge": "plant-a", "state": "silent", "last": map[string]any{"release": "0.27.0", "applied_serial": 7}}}
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := p.Handler()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(contextWithClient(r.Context(), b.Client())))
	}))
	jar, _ := cookiejar.New(nil)
	browser := pageSrv.Client()
	browser.Jar = jar
	browser.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(b.Certificate())
	return b, p, pageSrv, browser
}

func get(t *testing.T, c *http.Client, u string) (int, string, http.Header) {
	r, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(body), r.Header
}

func TestAnOperatorWithTheClientRoleSeesTheFleetAndNothingElse(t *testing.T) {
	_, _, srv, browser := rig(t)
	code, body, h := get(t, browser, srv.URL+"/")
	if code != 200 || !strings.Contains(body, "plant-a") || !strings.Contains(body, `class="r-silent"`) || !strings.Contains(body, `<span class="who">alice</span>`) {
		t.Fatalf("%d %s", code, body)
	}
	if strings.Contains(body, "<script") || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", h)
	}
	if strings.Contains(body, "<button") && strings.Count(body, "<form") != 1 {
		t.Fatal("the page offers an action besides signing out")
	}
}

func TestSignInsThatMustBeRefused(t *testing.T) {
	for name, bad := range map[string]func(c map[string]any){
		"no client role": func(c map[string]any) { c["resource_access"] = map[string]any{} },
		"a realm role only": func(c map[string]any) {
			c["resource_access"] = nil
			c["realm_access"] = map[string]any{"roles": []string{"fleet-operator"}}
		},
		"the role on another client": func(c map[string]any) {
			c["resource_access"] = map[string]any{"desk": map[string]any{"roles": []string{"fleet-operator"}}}
		},
		"another audience":         func(c map[string]any) { c["aud"] = "desk" },
		"another authorised party": func(c map[string]any) { c["azp"] = "desk" },
		"another sign-in's nonce":  func(c map[string]any) { c["nonce"] = "replayed" },
		"expired":                  func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"another issuer":           func(c map[string]any) { c["iss"] = "https://elsewhere" },
	} {
		t.Run(name, func(t *testing.T) {
			b, p, srv, browser := rig(t)
			b.claims = bad
			code, body, _ := get(t, browser, srv.URL+"/")
			if code != http.StatusForbidden || strings.Contains(body, "plant-a") {
				t.Fatalf("%d %s", code, body)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.sessions) != 0 {
				t.Fatal("a refused sign-in left a session")
			}
		})
	}
}

func TestACallbackWithoutTheStartingBrowserOrWithAnotherStateIsRefused(t *testing.T) {
	_, _, srv, browser := rig(t)
	if code, _, _ := get(t, browser, srv.URL+"/callback?code=c1&state=x"); code != http.StatusForbidden {
		t.Fatalf("a callback with no sign-in started: %d", code)
	}
	// A real sign-in up to the broker's answer (so the nonce is right), then the answer arrives with a forged state.
	stop := *browser
	stop.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == "/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	r, err := stop.Get(srv.URL + "/")
	if err != nil || r.StatusCode != http.StatusFound {
		t.Fatalf("no answer from the broker: %v", err)
	}
	r.Body.Close()
	answer, _ := url.Parse(r.Header.Get("Location"))
	q := answer.Query()
	q.Set("state", "forged")
	answer.RawQuery = q.Encode()
	if code, _, _ := get(t, browser, answer.String()); code != http.StatusForbidden {
		t.Fatalf("a forged state: %d", code)
	}
}

func TestSignOutAndBackChannelLogoutEndTheSession(t *testing.T) {
	b, p, srv, browser := rig(t)
	if code, _, _ := get(t, browser, srv.URL+"/"); code != 200 {
		t.Fatal("sign-in")
	}
	// The broker ends its session: a signed logout token naming its session id.
	lt := b.base("alice")
	delete(lt, "resource_access")
	lt["sid"], lt["events"] = "broker-session-1", map[string]any{logoutEvent: map[string]any{}}
	forged := b.base("alice")
	forged["sid"] = "broker-session-1" // no logout event: refused
	for _, tc := range []struct {
		claims map[string]any
		want   int
	}{{forged, 400}, {lt, 200}} {
		r, err := b.Client().PostForm(srv.URL+"/backchannel-logout", url.Values{"logout_token": {b.sign(t, tc.claims)}})
		if err != nil || r.StatusCode != tc.want {
			t.Fatalf("back-channel: %v %d, want %d", err, r.StatusCode, tc.want)
		}
	}
	p.mu.Lock()
	left := len(p.sessions)
	p.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d sessions after the broker's logout", left)
	}
	// Sign in again, then sign out.
	if code, _, _ := get(t, browser, srv.URL+"/"); code != 200 {
		t.Fatal("sign-in again")
	}
	r, _ := browser.PostForm(srv.URL+"/logout", nil)
	r.Body.Close()
	stop := *browser
	stop.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if code, _, _ := get(t, &stop, srv.URL+"/"); code != http.StatusFound {
		t.Fatalf("after sign-out the page still shows: %d", code)
	}
}

func TestASessionLastsFifteenMinutes(t *testing.T) {
	_, p, srv, browser := rig(t)
	if code, _, _ := get(t, browser, srv.URL+"/"); code != 200 {
		t.Fatal("sign-in")
	}
	p.Now = func() time.Time { return time.Now().Add(SessionTTL + time.Second) }
	stop := *browser
	stop.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if code, _, _ := get(t, &stop, srv.URL+"/"); code != http.StatusFound {
		t.Fatalf("an expired session still shows the page: %d", code)
	}
}

func TestTheBrokerClientReachesOnlyTheIssuerAndTrustsOnlyTheGivenRoots(t *testing.T) {
	b := newBroker(t)
	defer b.Close()
	pemCA := pemOf(b.Certificate().Raw)
	read := func(string) ([]byte, error) { return pemCA, nil }
	u, _ := url.Parse(b.URL)
	// The issuer names a host that does not resolve; the front setting dials the broker's real address.
	c, err := Client(Config{Issuer: "https://example.com:" + u.Port() + "/realms/r", CAFile: "ca", Front: u.Host}, read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("https://elsewhere.invalid/"); err == nil || !strings.Contains(err.Error(), "reaches only the broker") {
		t.Fatalf("another host: %v", err)
	}
	// Roots that are not the broker's: the broker is refused.
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another CA"}, IsCA: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c2, _ := Client(Config{Issuer: b.URL + "/realms/r", CAFile: "ca"}, func(string) ([]byte, error) { return pemOf(der), nil })
	if _, err := c2.Get(b.URL + "/.well-known/openid-configuration"); err == nil {
		t.Fatal("a certificate outside the given roots was trusted")
	}
	if _, err := c.Get("https://example.com:" + u.Port() + "/.well-known/openid-configuration"); err != nil {
		t.Fatalf("the broker through the front: %v", err)
	}
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A flood of anonymous visits leaves no state behind and cannot push out a sign-in in flight.
func TestAFloodOfVisitsDoesNotDenyASignInInFlight(t *testing.T) {
	_, p, srv, browser := rig(t)
	stop := *browser
	stop.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == "/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	r, err := stop.Get(srv.URL + "/") // the operator's sign-in, up to the broker's answer
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	answer := r.Header.Get("Location")
	flood := &http.Client{Transport: browser.Transport, // another browser: no cookie jar, never follows the redirect
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for range 2*maxEntries + 10 {
		if r, err := flood.Get(srv.URL + "/"); err == nil {
			r.Body.Close()
		}
	}
	p.mu.Lock()
	n := len(p.sessions)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("anonymous visits left %d entries", n)
	}
	if code, body, _ := get(t, browser, answer); code != 200 || !strings.Contains(body, "plant-a") {
		t.Fatalf("the sign-in in flight was lost: %d", code)
	}
}

func TestATamperedPendingCookieIsRefused(t *testing.T) {
	_, p, _, _ := rig(t)
	v := p.seal(pending{State: "s", Nonce: "n", Verifier: "v", At: time.Now().Unix()})
	b := []byte(v)
	b[len(b)-2] ^= 1
	if _, ok := p.open(string(b)); ok {
		t.Fatal("a tampered pending cookie opened")
	}
	if pd, ok := p.open(v); !ok || pd.State != "s" {
		t.Fatal("a good pending cookie did not open")
	}
}

func TestASignInLeftOverFiveMinutesIsRefused(t *testing.T) {
	_, p, srv, browser := rig(t)
	stop := *browser
	stop.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == "/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	r, err := stop.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	p.Now = func() time.Time { return time.Now().Add(pendingTTL + time.Minute) }
	if code, _, _ := get(t, browser, r.Header.Get("Location")); code != http.StatusForbidden {
		t.Fatalf("a stale sign-in was taken: %d", code)
	}
}

// One operator signing in again and again replaces their own oldest session, never another operator's (A4).
func TestOneOperatorCannotPushOutAnother(t *testing.T) {
	b, p, srv, browser := rig(t)
	if code, _, _ := get(t, browser, srv.URL+"/"); code != 200 { // alice
		t.Fatal("alice signs in")
	}
	b.claims = func(c map[string]any) { c["sub"], c["preferred_username"] = "mallory", "mallory" }
	for range 20 {
		other := &http.Client{Transport: browser.Transport}
		other.Jar, _ = cookiejar.New(nil)
		if code, _, _ := get(t, other, srv.URL+"/"); code != 200 {
			t.Fatal("mallory signs in")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := map[string]int{}
	for _, s := range p.sessions {
		n[s.sub]++
	}
	if n["alice"] != 1 || n["mallory"] != maxPerPerson {
		t.Fatalf("sessions per person: %v", n)
	}
}

// RFC 9207: the broker's answer names its issuer; another one is refused even with a right state (B5).
func TestAnAnswerFromAnotherIssuerIsRefused(t *testing.T) {
	_, _, srv, browser := rig(t)
	stop := *browser
	stop.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == "/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	r, err := stop.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	answer, _ := url.Parse(r.Header.Get("Location"))
	q := answer.Query()
	q.Set("iss", "https://evil.example/realms/x")
	answer.RawQuery = q.Encode()
	if code, _, _ := get(t, browser, answer.String()); code != http.StatusForbidden {
		t.Fatalf("an answer from another issuer: %d", code)
	}
}

// Opening a slot: a signed-in operator on the page's own origin, an anchored fleet; the code is shown once, the slot
// is listed, the action is in the evidence log. Without the session or from another origin: refused.
func TestOpeningASlot(t *testing.T) {
	_, p, srv, browser := rig(t)
	st, _ := admin.Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	p.Admin = st
	p.Cfg.EnrolURL, p.Cfg.Pin = "https://edge.example/fleet/v1/enrol", strings.Repeat("a", 64)
	if code, _, _ := get(t, browser, srv.URL+"/"); code != 200 {
		t.Fatal("sign-in")
	}
	post := func(c *http.Client, origin, name string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/slots", strings.NewReader(url.Values{"name": {name}, "kind": {"edge"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := post(browser, srv.URL, "plant-c"); code != 400 || !strings.Contains(body, "anchor it first") {
		t.Fatalf("before the anchor: %d %s", code, body)
	}
	r := registry.Registry{Fleet: "fleet-1", Version: 1, Officers: []registry.Officer{{ID: "ann"}, {ID: "bob"}, {ID: "cat"}}}
	_ = st.SetAnchor(registry.Accepted{Registry: r, Effective: time.Now().Add(-time.Hour)}, registry.Change{Registry: r}, admin.Event{})
	if code, _ := post(browser, "https://evil.example", "plant-c"); code != 403 {
		t.Fatalf("from another origin: %d", code)
	}
	if code, _ := post(&http.Client{Transport: browser.Transport}, srv.URL, "plant-c"); code != 403 {
		t.Fatalf("without a session: %d", code)
	}
	code, body := post(browser, srv.URL, "plant-c")
	if code != 200 || !strings.Contains(body, enrol.CodePrefix) {
		t.Fatalf("open: %d %s", code, body)
	}
	if _, page, _ := get(t, browser, srv.URL+"/"); !strings.Contains(page, "plant-c") || !strings.Contains(page, "waiting for the edge") || strings.Contains(page, enrol.CodePrefix) {
		t.Fatal("the slot is not listed, or the code is shown again")
	}
	if log := st.Log(1); len(log) != 1 || log[0].Action != "open slot" || log[0].Subject != "alice" {
		t.Fatalf("evidence log: %+v", log)
	}
}

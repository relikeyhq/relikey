// SPDX-License-Identifier: EUPL-1.2

// Package page is the fleet page (decision 0026 point 13): operators sign in at ReliKey's broker (OIDC code flow
// with PKCE, a client role on the fleet's own client) and see the inventory, read-only and without script. It
// listens on its own loopback port; the front proxies only /, /callback and /logout to it. The back-channel logout
// route is reached by the broker inside the pod, never through the front.
package page

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/fleet"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	SessionCookie = "__Host-relikey-fleet"
	PendingCookie = "__Host-relikey-fleet-pre"
	SessionTTL    = 15 * time.Minute
	pendingTTL    = 5 * time.Minute
	maxEntries    = 1000 // sessions; beyond it the oldest go
	maxPerPerson  = 5    // sessions per person: a sixth sign-in replaces that person's oldest
	logoutEvent   = "http://schemas.openid.net/event/backchannel-logout"
)

// Config is the page's part of fleet.json.
type Config struct {
	Listen      string `json:"listen"`       // loopback only
	Issuer      string `json:"issuer"`       // the broker's realm URL, as its tokens name it
	ClientID    string `json:"client_id"`    // the fleet's confidential client at the broker
	SecretFile  string `json:"secret_file"`  // its client secret, a file of its own
	RedirectURL string `json:"redirect_url"` // https://FLEET_HOST/callback
	Role        string `json:"role"`         // the client role that admits, "fleet-operator"
	CAFile      string `json:"ca_file"`      // the front's CA (or chain): the only roots the page trusts for the broker
	Front       string `json:"front"`        // the front on the pod's loopback, e.g. 127.0.0.1:8443: the broker is reached there
	// Enrolment (0026 point 15): where edges present their keys, and the fleet's CA, which the codes pin.
	EnrolURL  string `json:"enrol_url,omitempty"`   // https://EDGE_HOST/fleet/v1/enrol
	PinCAFile string `json:"pin_ca_file,omitempty"` // the fleet's CA (PEM): the codes pin it, never a leaf (point 27)
	// The first officers (points 16 and 30): broker usernames, at least three; each registers a passkey here and
	// signs the anchor. The installer names them; only they can complete the anchor.
	Officers []string `json:"officers,omitempty"`
}

// Client is the HTTP client the page reaches the broker with: only the given roots, and the issuer's host dialled
// at the front on the pod's loopback, so neither DNS nor a hairpin route matters.
func Client(cfg Config, read func(string) ([]byte, error)) (*http.Client, error) {
	pem, err := read(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("ca_file: no certificate in it")
	}
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("issuer: an https URL")
	}
	host := u.Host
	if u.Port() == "" {
		host += ":443"
	}
	t := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	d := &net.Dialer{Timeout: 10 * time.Second}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != host {
			return nil, fmt.Errorf("the page reaches only the broker (%s), not %s", host, addr)
		}
		if cfg.Front != "" {
			addr = cfg.Front
		}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: t, Timeout: 20 * time.Second}, nil
}

// WithClient makes the OIDC and OAuth libraries use c.
func WithClient(ctx context.Context, c *http.Client) context.Context {
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, c), c)
}

// Edges gives the page what it shows: the inventory's basis and its edges, as the JSON route gives them.
type Edges func() (basis string, edges any)

// pending is a sign-in in flight. It lives only in the browser, sealed (AES-GCM, a key made at start): the page
// keeps no state for anonymous visitors, so no flood of visits can push out an operator's sign-in.
type pending struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	At       int64  `json:"t"`
}

func (p *Page) seal(pd pending) string {
	raw, _ := json.Marshal(pd)
	n := make([]byte, p.aead.NonceSize())
	_, _ = rand.Read(n)
	return base64.RawURLEncoding.EncodeToString(p.aead.Seal(n, n, raw, []byte(PendingCookie)))
}

func (p *Page) open(v string) (pending, bool) {
	var pd pending
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(b) < p.aead.NonceSize() {
		return pd, false
	}
	raw, err := p.aead.Open(nil, b[:p.aead.NonceSize()], b[p.aead.NonceSize():], []byte(PendingCookie))
	if err != nil || json.Unmarshal(raw, &pd) != nil {
		return pd, false
	}
	return pd, true
}

type session struct {
	sub, brokerSID, name string
	until                time.Time
}

// Page serves the fleet page.
type Page struct {
	Cfg      Config
	OAuth    oauth2.Config
	Verifier *oidc.IDTokenVerifier
	Edges    Edges
	Log      *slog.Logger
	Now      func() time.Time
	HTTP     *http.Client // to the broker; nil: the request's context decides (tests)
	Admin    *admin.Store // the registry, slots and evidence log; nil: no enrolment on this page
	Pin      string       // what the codes pin: enrol.CAPin of Cfg.PinCAFile, set by the fleet service at start

	aead        cipher.AEAD // seals pending sign-ins; a restart voids those in flight (start again)
	mu          sync.Mutex
	sessions    map[string]session
	challenges  map[string]challenge         // passkey registrations in flight, by session
	activations map[string]pendingActivation // activations being signed, by session
}

// New discovers the broker and builds the page. secret is the client secret's content.
func New(ctx context.Context, cfg Config, secret string, edges Edges, log *slog.Logger) (*Page, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("the broker at %s: %w", cfg.Issuer, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &Page{
		aead: aead,
		Cfg:  cfg,
		OAuth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(),
			RedirectURL: cfg.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile"}},
		Verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		Edges:    edges, Log: log, Now: time.Now,
	}, nil
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Handler is the page's routes: what the front proxies, and the back-channel logout for the broker in the pod.
func (p *Page) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", p.index)
	m.HandleFunc("GET /callback", p.callback)
	m.HandleFunc("POST /logout", p.logout)
	m.HandleFunc("POST /slots", p.openSlot)
	m.HandleFunc("POST /officer/begin", p.officerBegin)
	m.HandleFunc("POST /officer/finish", p.officerFinish)
	m.HandleFunc("POST /anchor/begin", p.anchorBegin)
	m.HandleFunc("POST /anchor/sign", p.anchorSign)
	m.HandleFunc("POST /activate/begin", p.activateBegin)
	m.HandleFunc("POST /activate/sign", p.activateSign)
	m.HandleFunc("POST /backchannel-logout", p.backchannel)
	return fleet.LoopbackOnly(headers(m)) // DNS rebinding: loopback names only (the front sets Host)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src '"+styleHash+"'; script-src '"+scriptHash+"'; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func cookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode}) // Lax: the broker's redirect to /callback must carry it
}

func clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode})
}

// prune drops expired entries and, past the cap, the oldest. The caller holds mu.
func prune[V any](m map[string]V, expired func(V) bool, at func(V) time.Time) {
	for k, v := range m {
		if expired(v) {
			delete(m, k)
		}
	}
	for len(m) >= maxEntries {
		oldest := ""
		for k, v := range m {
			if oldest == "" || at(v).Before(at(m[oldest])) {
				oldest = k
			}
		}
		delete(m, oldest)
	}
}

func (p *Page) current(r *http.Request) (session, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return session{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[c.Value]
	if !ok || !p.Now().Before(s.until) {
		delete(p.sessions, c.Value)
		return session{}, false
	}
	return s, true
}

func (p *Page) index(w http.ResponseWriter, r *http.Request) {
	if s, ok := p.current(r); ok {
		basis, edges := p.Edges()
		raw, _ := json.Marshal(edges)
		var rows []map[string]any
		_ = json.Unmarshal(raw, &rows)
		v := board(rows, p.Now())
		v.Name, v.Basis, v.Style, v.Mark = s.name, basis, template.CSS(style), mark
		v.Enrol = p.enrolView(s)
		v.Anchor = p.anchorView(s)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = view.Execute(w, v)
		return
	}
	pd := pending{State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier(), At: p.Now().Unix()}
	cookie(w, PendingCookie, p.seal(pd), pendingTTL)
	http.Redirect(w, r, p.OAuth.AuthCodeURL(pd.State, oidc.Nonce(pd.Nonce), oauth2.S256ChallengeOption(pd.Verifier)),
		http.StatusFound)
}

func (p *Page) refuse(w http.ResponseWriter, why string, err error) {
	p.Log.Warn("fleet page sign-in refused", "why", why, "err", err)
	http.Error(w, "Sign-in refused: "+why+". Open the fleet page again to start over.", http.StatusForbidden)
}

func (p *Page) callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(PendingCookie)
	if err != nil {
		p.refuse(w, "no sign-in was started in this browser", err)
		return
	}
	clear(w, PendingCookie) // one use: the broker's code is single-use too
	pd, ok := p.open(c.Value)
	if !ok || p.Now().Sub(time.Unix(pd.At, 0)) > pendingTTL {
		p.refuse(w, "the sign-in expired", nil)
		return
	}
	// RFC 9207: an answer naming another issuer is refused (OAuth mix-up; GUI red team 2026-10-25, B5). Keycloak
	// sends iss; one that does not is held to the ID token's issuer check below.
	if iss := r.URL.Query().Get("iss"); iss != "" && iss != p.Cfg.Issuer {
		p.refuse(w, "the answer comes from another issuer", nil)
		return
	}
	if r.URL.Query().Get("state") != pd.State {
		p.refuse(w, "the answer does not belong to this sign-in", nil)
		return
	}
	ctx := r.Context()
	if p.HTTP != nil {
		ctx = WithClient(ctx, p.HTTP)
	}
	tok, err := p.OAuth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pd.Verifier))
	if err != nil {
		p.refuse(w, "the broker did not exchange the code", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier.Verify(ctx, raw) // issuer, audience, expiry, signature
	if err != nil {
		p.refuse(w, "the ID token did not verify", err)
		return
	}
	var cl struct {
		Nonce    string                              `json:"nonce"`
		AZP      string                              `json:"azp"`
		SID      string                              `json:"sid"`
		Name     string                              `json:"preferred_username"`
		Resource map[string]struct{ Roles []string } `json:"resource_access"`
	}
	if err := idt.Claims(&cl); err != nil {
		p.refuse(w, "the ID token's claims are unreadable", err)
		return
	}
	switch {
	case cl.Nonce != pd.Nonce:
		p.refuse(w, "the ID token belongs to another sign-in", nil)
		return
	case cl.AZP != "" && cl.AZP != p.Cfg.ClientID:
		p.refuse(w, "the ID token was issued to another client", nil)
		return
	case !slices.Contains(cl.Resource[p.Cfg.ClientID].Roles, p.Cfg.Role):
		p.refuse(w, "this account does not hold the role "+p.Cfg.Role+" on the fleet's client", nil)
		return
	}
	id := random() // a fresh session id: nothing from before the sign-in carries over
	p.mu.Lock()
	if p.sessions == nil {
		p.sessions = map[string]session{}
	}
	prune(p.sessions, func(v session) bool { return !p.Now().Before(v.until) }, func(v session) time.Time { return v.until })
	mine, oldest := 0, ""
	for k, v := range p.sessions { // one operator's sign-ins never push out another's (GUI red team 2026-10-25, A4)
		if v.sub == idt.Subject {
			mine++
			if oldest == "" || v.until.Before(p.sessions[oldest].until) {
				oldest = k
			}
		}
	}
	if mine >= maxPerPerson {
		delete(p.sessions, oldest)
	}
	p.sessions[id] = session{sub: idt.Subject, brokerSID: cl.SID, name: cl.Name, until: p.Now().Add(SessionTTL)}
	p.mu.Unlock()
	cookie(w, SessionCookie, id, SessionTTL)
	p.Log.Info("fleet page sign-in", "sub", idt.Subject)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *Page) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		p.mu.Lock()
		delete(p.sessions, c.Value)
		p.mu.Unlock()
	}
	clear(w, SessionCookie)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Signed out of the fleet page.\n"))
}

// backchannel ends the sessions the broker names in a signed logout token (OIDC Back-Channel Logout 1.0).
func (p *Page) backchannel(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	raw := r.PostFormValue("logout_token")
	tok, err := p.Verifier.Verify(r.Context(), raw)
	if err != nil {
		http.Error(w, "logout token refused", http.StatusBadRequest)
		return
	}
	var cl struct {
		SID    string                     `json:"sid"`
		Nonce  *string                    `json:"nonce"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := tok.Claims(&cl); err != nil || cl.Nonce != nil || cl.Events[logoutEvent] == nil || (cl.SID == "" && tok.Subject == "") {
		http.Error(w, "logout token refused", http.StatusBadRequest)
		return
	}
	n := 0
	p.mu.Lock()
	for k, s := range p.sessions {
		if (cl.SID != "" && s.brokerSID == cl.SID) || (cl.SID == "" && s.sub == tok.Subject) {
			delete(p.sessions, k)
			n++
		}
	}
	p.mu.Unlock()
	p.Log.Info("fleet page back-channel logout", "sessions", n)
	w.WriteHeader(http.StatusOK)
}

// ReadSecret reads the client secret: a file of its own, never in fleet.json.
func ReadSecret(read func(string) ([]byte, error), path string) (string, error) {
	b, err := read(path)
	if err != nil {
		return "", err
	}
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "", errors.New("the client secret file is empty")
	}
	return s, nil
}

// edgeRow is one edge as the page shows it.
type edgeRow struct {
	Edge, State, Lamp, Release, Age string
	Behind, Serial, Leases          int
	Drift                           []string
	Reported                        bool
}

// fleetView is what the page renders: the edges worst first, and the counts the summary line says.
type fleetView struct {
	Name, Basis, Newest                        string
	Rows                                       []edgeRow
	Total, Reporting, Silent, Never, WithDrift int
	Style                                      template.CSS
	Mark                                       template.HTML
	Enrol                                      *enrolView
	Anchor                                     *anchorView
}

// lampOrder sorts the edges: silent first, then never reported, then drift, then in order.
var lampOrder = map[string]int{"silent": 0, "never": 1, "drift": 2, "ok": 3}

// board builds the view from the inventory's edges (as the JSON route gives them), as of now.
func board(rows []map[string]any, now time.Time) fleetView {
	var v fleetView
	num := func(m map[string]any, k string) int { f, _ := m[k].(float64); return int(f) }
	for _, r := range rows {
		e := edgeRow{Edge: fmt.Sprint(r["edge"]), State: fmt.Sprint(r["state"])}
		if last, ok := r["last"].(map[string]any); ok {
			e.Reported, e.Release = true, fmt.Sprint(last["release"])
			e.Serial, e.Leases = num(last, "applied_serial"), num(last, "live_leases")
			for _, d := range asList(last["drift_codes"]) {
				e.Drift = append(e.Drift, fmt.Sprint(d))
			}
		}
		if seen, err := time.Parse(time.RFC3339Nano, fmt.Sprint(r["last_seen"])); err == nil && !seen.IsZero() && e.Reported {
			e.Age = ago(now.Sub(seen))
		}
		switch {
		case e.State == "silent":
			e.Lamp = "silent"
			v.Silent++
		case !e.Reported:
			e.Lamp = "never"
			v.Never++
		case len(e.Drift) > 0:
			e.Lamp = "drift"
			v.WithDrift++
		default:
			e.Lamp = "ok"
		}
		if e.Reported && e.State != "silent" {
			v.Reporting++
		}
		v.Rows = append(v.Rows, e)
	}
	// Releases behind: how many distinct newer releases the fleet runs (decision 0026 point 10: at most two).
	var releases []string
	for _, e := range v.Rows {
		if e.Release != "" && !slices.Contains(releases, e.Release) {
			releases = append(releases, e.Release)
		}
	}
	slices.SortFunc(releases, func(a, b string) int { return compareRelease(b, a) })
	if len(releases) > 0 {
		v.Newest = releases[0]
	}
	for i := range v.Rows {
		if r := v.Rows[i].Release; r != "" {
			v.Rows[i].Behind = slices.Index(releases, r)
		}
	}
	slices.SortStableFunc(v.Rows, func(a, b edgeRow) int {
		if c := lampOrder[a.Lamp] - lampOrder[b.Lamp]; c != 0 {
			return c
		}
		return strings.Compare(a.Edge, b.Edge)
	})
	v.Total = len(v.Rows)
	return v
}

func asList(v any) []any { l, _ := v.([]any); return l }

// compareRelease compares dotted release numbers numerically ("0.27.0" > "0.9.1"); anything else as text.
func compareRelease(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x - y
		}
	}
	return strings.Compare(a, b)
}

func ago(d time.Duration) string {
	switch d = d.Round(time.Second); {
	case d < time.Minute:
		return fmt.Sprintf("%d s ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %02d min ago", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

// The brand's small mark, as the edge status page carries it (TestThePageMarkIsTheBrandMark checks both).
const (
	markBowl  = "M13 8h20a14 14 0 0 1 0 28H21v20h-8zM21 16v12h12a6 6 0 0 0 0-12z"
	markLeg   = "M25 31L34 31L38.68 40L29.68 40z"
	markBlade = "M29.68 40L38.68 40L40.24 43L44.74 43L46.82 47L42.32 47L43.88 50L48.38 50L50.46 54L45.96 54L47 56L38 56z"
)

var mark = template.HTML(`<svg viewBox="0 0 64 64" role="img" aria-label="ReliKey"><path class="i" fill-rule="evenodd" d="` +
	markBowl + `"/><path class="i" d="` + markLeg + `"/><path class="a" d="` + markBlade + `"/></svg>`)

const style = `:root{--bg:#f2f4f7;--card:#fff;--ink:#17142b;--soft:#5b5f72;--line:#d9dde5;--ok:#18794e;--warn:#9a5b00;--warnbg:#fdf1dc;--bad:#b42318;--badbg:#fdecea;--key:#c85d16}
@media (prefers-color-scheme:dark){:root{--bg:#0f1420;--card:#171d2b;--ink:#f4f5f8;--soft:#a3abbd;--line:#2c3448;--ok:#4cc38a;--warn:#f0b24a;--warnbg:#2c2210;--bad:#ff6b5e;--badbg:#311613;--key:#f0954f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "IBM Plex Sans",ui-sans-serif,system-ui,"Segoe UI",sans-serif;font-variant-numeric:tabular-nums}
main{max-width:1080px;margin:0 auto;padding:22px 16px 40px}
header{display:flex;align-items:center;gap:12px}header svg{width:34px;height:34px;flex:none}.i{fill:var(--ink)}.a{fill:var(--key)}
h1{font-size:22px;margin:0;font-weight:650;flex:1}
form{margin:0}button{font:inherit;font-size:14px;color:var(--ink);background:var(--card);border:1px solid var(--line);padding:5px 12px;cursor:pointer}
button:hover{border-color:var(--key)}button:focus-visible{outline:2px solid var(--key);outline-offset:2px}
.who{color:var(--soft);font-size:14px;margin-right:4px}
.sum{font-size:18px;margin:18px 0 4px}.sum b{font-weight:650}.sum .bad{color:var(--bad)}.sum .warn{color:var(--warn)}
.basis{color:var(--soft);margin:0 0 16px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--soft);font-weight:500;font-size:13px}td.n{text-align:right}th.n{text-align:right}
.lamp{display:inline-block;width:12px;height:12px;margin-right:10px;vertical-align:-1px;background:var(--ok)}
.r-silent .lamp{background:var(--bad);box-shadow:0 0 0 3px var(--badbg)}.r-never .lamp{background:transparent;border:2px solid var(--soft)}.r-drift .lamp{background:var(--warn)}
.r-silent td{background:var(--badbg)}.edge{font-weight:650}.st{color:var(--soft);font-size:13px;display:block;margin-left:22px}
.r-silent .st{color:var(--bad);font-weight:650}.behind{color:var(--warn);font-size:13px;margin-left:6px}
.code{display:inline-block;font-size:12px;padding:0 7px;margin:1px 4px 1px 0;border:1px solid var(--warn);color:var(--warn)}
.none{color:var(--soft)}h2.sec{font-size:18px;margin:28px 0 8px}
form.open{display:flex;flex-wrap:wrap;gap:10px;align-items:end;margin:0 0 12px}form.open label{display:flex;flex-direction:column;font-size:13px;color:var(--soft)}
input,select{font:inherit;color:var(--ink);background:var(--card);border:1px solid var(--line);padding:5px 8px}
.code-box{white-space:pre-wrap;word-break:break-all;background:var(--card);border:1px solid var(--line);padding:14px;font:14px ui-monospace,Consolas,monospace}
a{color:var(--key)}footer{margin-top:20px;color:var(--soft);font-size:12px}
@media (max-width:720px){thead{display:none}table,tbody,tr,td{display:block}tr{border-bottom:1px solid var(--line);padding:8px 0}
td{border:0;padding:2px 14px}td.n{text-align:left}td[data-k]::before{content:attr(data-k) " ";color:var(--soft)}.r-never td[data-k]{display:none}}`

var styleHash = func() string {
	h := sha256.Sum256([]byte(style))
	return "sha256-" + base64.StdEncoding.EncodeToString(h[:])
}()

var view = template.Must(template.New("fleet").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReliKey fleet</title><style>{{.Style}}</style></head><body><main>
<header>{{.Mark}}<h1>Fleet</h1><span class="who">{{.Name}}</span><form method="post" action="/logout"><button>Sign out</button></form></header>
<p class="sum">{{.Total}} edge{{if ne .Total 1}}s{{end}}: <b>{{.Reporting}} reporting</b>{{if .Silent}}, <b class="bad">{{.Silent}} silent</b>{{end}}{{if .Never}}, <b>{{.Never}} never reported</b>{{end}}{{if .WithDrift}}, <b class="warn">{{.WithDrift}} with drift</b>{{end}}.</p>
<p class="basis">What each edge says about itself: {{.Basis}}.{{if .Newest}} Newest release in the fleet: {{.Newest}}.{{end}}</p>
<table><thead><tr><th>Edge</th><th>Release</th><th class="n">Bundle</th><th class="n">Live leases</th><th>Drift</th><th>Last report</th></tr></thead><tbody>
{{range .Rows}}<tr class="r-{{.Lamp}}"><td><span class="lamp"></span><span class="edge">{{.Edge}}</span><span class="st">{{if eq .Lamp "silent"}}silent: no report within the window{{else if eq .Lamp "never"}}never reported{{else if eq .Lamp "drift"}}reporting, with drift{{else}}reporting{{end}}</span></td>
<td data-k="Release">{{if .Release}}{{.Release}}{{if .Behind}}<span class="behind">{{.Behind}} behind</span>{{end}}{{else}}<span class="none">-</span>{{end}}</td>
<td class="n" data-k="Bundle">{{if .Reported}}{{.Serial}}{{else}}<span class="none">-</span>{{end}}</td>
<td class="n" data-k="Live leases">{{if .Reported}}{{.Leases}}{{else}}<span class="none">-</span>{{end}}</td>
<td>{{range .Drift}}<span class="code">{{.}}</span>{{end}}</td>
<td data-k="Last report">{{if .Age}}{{.Age}}{{else}}<span class="none">-</span>{{end}}</td></tr>
{{else}}<tr><td colspan="6">No edge is known yet: make one known with <code>deploy/core/fleet_edge.py</code>.</td></tr>{{end}}
</tbody></table>
{{with .Enrol}}<h2 class="sec">Enrolment</h2>
{{if not .Anchored}}<p class="basis">The fleet has no officers yet: anchor it before any edge can be enrolled.</p>
{{with $.Anchor}}<h2 class="sec">Anchor</h2>
<p class="basis">The first officers each register a passkey for fleet statements, then each signs the officer list with it.
Until all have signed, no edge can be enrolled. Check that the list below is the people you expect before you sign.</p>
{{if .TooFew}}<p><b class="bad">The installer names fewer than three first officers.</b> Name at least three in fleet.json
(officers) and restart the fleet.</p>{{end}}
<table><thead><tr><th>Officer</th><th>Passkey</th><th>Anchor</th></tr></thead><tbody>
{{range .Named}}<tr><td><span class="edge">{{.Name}}</span></td><td data-k="Passkey">{{if .Alarm}}<b class="bad">{{.Passkey}}</b>{{else}}{{.Passkey}}{{end}}</td><td data-k="Anchor">{{if .Signed}}signed{{else if .Registered}}<span class="none">not signed</span>{{else}}<span class="none">-</span>{{end}}</td></tr>
{{end}}</tbody></table>
{{if .Hash}}<p class="basis">Officer list version 1, fingerprint {{.Hash}}; it can be signed until {{.Until}}.</p>{{end}}
{{if .MeNamed}}<p class="open">{{if .MeSign}}<button type="button" id="anchor-sign">Sign the officer list with my passkey</button> {{end}}<button type="button" id="officer-register">{{if .MeHas}}Replace my officer passkey{{else}}Register my officer passkey{{end}}</button></p>
<p id="anchor-msg" role="status" aria-live="polite"></p><noscript><p>The passkey steps need JavaScript in this browser.</p></noscript>
<script>{{.Script}}</script>{{else}}<p class="basis">You are not one of the named first officers: they register and sign here.</p>{{end}}{{end}}
{{else}}<form method="post" action="/slots" class="open"><label>Name <input name="name" required pattern="[a-z0-9][a-z0-9-]{0,62}" maxlength="63"></label>
<label>Kind <select name="kind"><option value="edge">edge</option><option value="relay">relay</option><option value="site">site fleet</option></select></label>
<button>Open a slot</button></form>
{{if .Slots}}<table><thead><tr><th>Slot</th><th>State</th><th>Opened by</th><th>Open until</th></tr></thead><tbody>
{{range .Slots}}<tr><td><span class="edge">{{.Name}}</span><span class="st">{{.Kind}}</span></td><td>{{.State}}{{if .Fingerprint}}<span class="st">{{.Fingerprint}}</span>{{end}}{{if .Refused}}<span class="behind">{{.Refused}} refused</span>{{end}}</td>
<td data-k="Opened by">{{.OpenedBy}}</td><td data-k="Open until">{{.Expires}}</td></tr>{{end}}
</tbody></table>{{end}}
{{if .Presented}}<h2 class="sec">Approve</h2>
{{if .MeOfficer}}<p class="basis">For each edge to admit: type 16 characters of the fingerprint (not the last 16, which carry
less), or all of it, exactly as read from the edge's own screen, not from this page, and record who read it and how. A relay or site fleet is admitted only when you
read its screen yourself, on site. Then sign with your officer passkey: up to ten at once.</p>
<form id="activate"><table><thead><tr><th>Admit</th><th>Fingerprint, as read from the edge</th><th>Read by</th><th>How</th></tr></thead><tbody>
{{range .Presented}}<tr data-slot="{{.ID}}"><td><label><input type="checkbox" name="admit"> <span class="edge">{{.Name}}</span></label><span class="st">{{.Kind}}, from {{.Source}}</span></td>
<td data-k="Fingerprint"><input name="typed" autocomplete="off" spellcheck="false" minlength="16" maxlength="80" aria-label="fingerprint characters for {{.Name}}"></td>
<td data-k="Read by"><input name="read_by" maxlength="120" aria-label="who read the screen of {{.Name}}"></td>
<td data-k="How"><select name="read_how" aria-label="how the screen of {{.Name}} was read"><option>on site</option><option>phone</option><option>video call</option><option>message</option></select></td></tr>{{end}}
</tbody></table></form>
<p class="open"><button type="button" id="activate-sign">Admit the selected with my officer passkey</button></p>
<p id="activate-msg" role="status" aria-live="polite"></p><noscript><p>The passkey step needs JavaScript in this browser.</p></noscript>
<script>{{.Script}}</script>{{else}}<p class="basis">Keys are waiting for approval: an officer admits them here with their officer passkey.</p>{{end}}{{end}}{{end}}{{end}}
<footer>This page commands no edge: a slot it opens admits nothing until an officer approves with their passkey. It does not refresh on its own; reload to see the latest reports.</footer>
</main></body></html>
`))

// enrolView is the page's enrolment section: whether the fleet is anchored, and its slots.
type enrolView struct {
	Anchored  bool
	Slots     []slotRow
	Error     string
	Presented []presentedRow // keys awaiting approval
	MeOfficer bool           // the signed-in person is an officer of the registry in force
	Script    template.JS
}

// presentedRow is a slot whose edge presented its key, with the source address it came from (point 15). The officer
// types the fingerprint as read from the edge's own screen: no tap-to-approve.
type presentedRow struct {
	ID, Name, Kind, Source string
}

type slotRow struct {
	Name, Kind, State, OpenedBy, Expires, Fingerprint string
	Refused                                           int
}

func (p *Page) enrolView(s session) *enrolView {
	if p.Admin == nil {
		return nil
	}
	now := p.Now()
	v := &enrolView{Anchored: p.Admin.Anchor() != "", Script: template.JS(script)}
	_, _, v.MeOfficer = p.officer(s)
	for _, sl := range p.Admin.Slots() {
		r := slotRow{Name: sl.Name, Kind: string(sl.Kind), OpenedBy: sl.OpenedBy, Expires: sl.Expires.UTC().Format("2006-01-02 15:04Z"),
			Refused: len(sl.Refused)}
		switch {
		case sl.Active:
			r.State = "active"
		case sl.Key != "" && now.Before(sl.Expires):
			r.State, r.Fingerprint = "key presented, awaiting approval", enrol.Fingerprint(sl.Key)
			v.Presented = append(v.Presented, presentedRow{ID: sl.ID, Name: sl.Name, Kind: string(sl.Kind), Source: sl.Source})
		case !now.Before(sl.Expires):
			r.State = "expired"
		default:
			r.State = "waiting for the edge"
		}
		v.Slots = append(v.Slots, r)
	}
	return v
}

// sameOrigin: a state-changing form comes from the page itself (the Lax session cookie already keeps other sites'
// forms out; this checks it once more).
func (p *Page) sameOrigin(r *http.Request) bool {
	u, err := url.Parse(p.Cfg.RedirectURL)
	return err == nil && r.Header.Get("Origin") == u.Scheme+"://"+u.Host
}

// openSlot opens an enrolment slot and shows its code once (point 15): a session action, logged (point 26).
func (p *Page) openSlot(w http.ResponseWriter, r *http.Request) {
	s, ok := p.current(r)
	if !ok || p.Admin == nil || !p.sameOrigin(r) {
		http.Error(w, "Sign in on the fleet page first.", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	name, kind := r.PostFormValue("name"), enrol.Kind(r.PostFormValue("kind"))
	ev := admin.Event{At: p.Now(), Subject: s.sub, Source: r.Header.Get("X-Forwarded-For")}
	sl, code, err := p.Admin.OpenSlot(p.Cfg.EnrolURL, p.Pin, name, kind, "basic", ev, p.Now())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = codeView.Execute(w, map[string]any{"Error": err.Error(), "Style": template.CSS(style), "Mark": mark})
		return
	}
	_ = codeView.Execute(w, map[string]any{"Slot": sl, "Code": code.String(), "Style": template.CSS(style), "Mark": mark})
}

var codeView = template.Must(template.New("code").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReliKey enrolment code</title><style>{{.Style}}</style></head><body><main>
<header>{{.Mark}}<h1>Enrolment</h1></header>
{{if .Error}}<p class="sum"><b class="bad">The slot was not opened.</b></p><p>{{.Error}}</p>
{{else}}<p class="sum">Slot for <b>{{.Slot.Name}}</b> ({{.Slot.Kind}}), open until {{.Slot.Expires.UTC.Format "2006-01-02 15:04Z"}}.</p>
<p class="basis">Give this code to the installer, as a QR code or on a USB stick, not by phone. It is shown once: this page
cannot show it again. The installer runs the edge installer with it; the edge then shows its key's fingerprint, and an
officer approves with their passkey.</p>
<pre class="code-box">{{.Code}}</pre>{{end}}
<p><a href="/">Back to the fleet</a></p>
</main></body></html>
`))

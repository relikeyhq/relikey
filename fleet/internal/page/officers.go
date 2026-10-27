// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/registry"
)

// The anchor ceremony (decision 0026 points 16, 21 and 30): the installer names the first officers (fleet.json
// "officers", broker usernames, at least three); each registers a passkey on this page at their first sign-in, for
// fleet statements only; once all have, every one of them signs registry version 1 with it. The page holds no key
// and can complete nothing alone. The passkey steps need the browser's WebAuthn API, so this part of the page carries
// one small script, allowed by its hash and nothing else.

const (
	challengeTTL = 5 * time.Minute
	maxJSON      = 16 << 10 // a WebAuthn answer, RSA keys and long credential ids included
	ceremonyMS   = 120000   // how long the browser's passkey prompt waits
)

type challenge struct {
	value []byte
	until time.Time
}

var b64 = base64.RawURLEncoding

// rp is the relying party: the page's own origin, as the broker redirects to it.
func (p *Page) rp() registry.RP {
	u, _ := url.Parse(p.Cfg.RedirectURL)
	return registry.RP{ID: u.Hostname(), Origin: u.Scheme + "://" + u.Host}
}

func (p *Page) sessionID(r *http.Request) string {
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, why string) {
	writeJSON(w, status, map[string]string{"error": why})
}

// ceremony admits a passkey step: a session, on the page's own origin, sending JSON (a form from elsewhere cannot),
// before the fleet is anchored. It decodes the body into v.
func (p *Page) ceremony(w http.ResponseWriter, r *http.Request, v any) (session, bool) {
	s, ok := p.current(r)
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case !ok || p.Admin == nil || !p.sameOrigin(r):
		fail(w, http.StatusForbidden, "sign in on the fleet page first")
		return s, false
	case ct != "application/json":
		fail(w, http.StatusUnsupportedMediaType, "the page sends JSON")
		return s, false
	case p.Admin.Anchor() != "":
		fail(w, http.StatusConflict, "the fleet is anchored already: officers change through the registry")
		return s, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSON)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "the request is not what the page sends")
		return s, false
	}
	return s, true
}

func (p *Page) named(name string) bool { return slices.Contains(p.Cfg.Officers, name) }

type credDesc struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// officerBegin starts a passkey registration for a named first officer: the creation options, with a fresh challenge
// kept for this session for five minutes.
func (p *Page) officerBegin(w http.ResponseWriter, r *http.Request) {
	var none struct{}
	s, ok := p.ceremony(w, r, &none)
	if !ok {
		return
	}
	if !p.named(s.name) {
		fail(w, http.StatusForbidden, "you are not named as a first officer: the installer names them in fleet.json (officers)")
		return
	}
	ch := make([]byte, 32)
	_, _ = rand.Read(ch)
	p.mu.Lock()
	if p.challenges == nil {
		p.challenges = map[string]challenge{}
	}
	prune(p.challenges, func(c challenge) bool { return !p.Now().Before(c.until) }, func(c challenge) time.Time { return c.until })
	p.challenges[p.sessionID(r)] = challenge{value: ch, until: p.Now().Add(challengeTTL)}
	p.mu.Unlock()
	var exclude []credDesc // one authenticator, one officer: the browser refuses a device already holding another's
	for _, o := range p.Admin.Candidates() {
		exclude = append(exclude, credDesc{"public-key", o.CredentialID})
	}
	user := sha256.Sum256([]byte("relikey-fleet-officer\n" + s.sub))
	rp := p.rp()
	writeJSON(w, http.StatusOK, map[string]any{
		"rp":                     map[string]string{"id": rp.ID, "name": "ReliKey fleet"},
		"user":                   map[string]string{"id": b64.EncodeToString(user[:]), "name": s.name, "displayName": s.name + " (fleet officer)"},
		"challenge":              b64.EncodeToString(ch),
		"pubKeyCredParams":       []map[string]any{{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}},
		"authenticatorSelection": map[string]string{"userVerification": "required", "residentKey": "discouraged"},
		"attestation":            "none",
		"timeout":                ceremonyMS,
		"excludeCredentials":     exclude,
	})
}

// officerFinish verifies the registration against this session's challenge (once) and records the passkey.
func (p *Page) officerFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientDataJSON    string `json:"client_data_json"`
		AttestationObject string `json:"attestation_object"`
	}
	s, ok := p.ceremony(w, r, &in)
	if !ok {
		return
	}
	if !p.named(s.name) {
		fail(w, http.StatusForbidden, "you are not named as a first officer: the installer names them in fleet.json (officers)")
		return
	}
	p.mu.Lock()
	ch, had := p.challenges[p.sessionID(r)]
	delete(p.challenges, p.sessionID(r)) // one use, whatever the outcome
	p.mu.Unlock()
	if !had || !p.Now().Before(ch.until) {
		fail(w, http.StatusBadRequest, "the registration expired or was not started here: start it again")
		return
	}
	cd, err1 := b64.DecodeString(in.ClientDataJSON)
	att, err2 := b64.DecodeString(in.AttestationObject)
	if err := errors.Join(err1, err2); err != nil {
		fail(w, http.StatusBadRequest, "the passkey's answer is not base64url")
		return
	}
	c, err := p.rp().VerifyRegistration(cd, att, ch.value)
	if err != nil {
		p.Log.Warn("officer passkey refused", "sub", s.sub, "err", err)
		fail(w, http.StatusBadRequest, "the passkey was not registered: "+err.Error())
		return
	}
	o := registry.Officer{ID: s.sub, Name: s.name, CredentialID: b64.EncodeToString(c.ID), PublicKey: b64.EncodeToString(c.Key), DeviceBound: c.DeviceBound}
	if err := p.Admin.Register(o, admin.Event{At: p.Now(), Subject: s.sub, Source: r.Header.Get("X-Forwarded-For")}); err != nil {
		fail(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registered": true, "device_bound": c.DeviceBound})
}

// draft is the anchor being signed, if every named officer has registered.
func (p *Page) draft() (registry.Change, bool, error) {
	return p.Admin.Draft(p.Cfg.Officers, random(), p.Now())
}

// anchorBegin gives an officer named in the drafted anchor the request to sign it: the statement's challenge, for
// their own passkey only.
func (p *Page) anchorBegin(w http.ResponseWriter, r *http.Request) {
	var none struct{}
	s, ok := p.ceremony(w, r, &none)
	if !ok {
		return
	}
	d, ok, err := p.draft()
	switch {
	case err != nil:
		fail(w, http.StatusConflict, err.Error())
		return
	case !ok:
		fail(w, http.StatusConflict, "not every named officer has registered a passkey yet")
		return
	}
	i := slices.IndexFunc(d.Registry.Officers, func(o registry.Officer) bool { return o.ID == s.sub })
	if i < 0 {
		fail(w, http.StatusForbidden, "you are not one of the officers this anchor names")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":        b64.EncodeToString(d.Statement.Challenge()),
		"rpId":             p.rp().ID,
		"allowCredentials": []credDesc{{"public-key", d.Registry.Officers[i].CredentialID}},
		"userVerification": "required",
		"timeout":          ceremonyMS,
	})
}

// anchorSign takes an officer's signature over the drafted anchor; with the last one the fleet is anchored.
func (p *Page) anchorSign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientDataJSON    string `json:"client_data_json"`
		AuthenticatorData string `json:"authenticator_data"`
		Signature         string `json:"signature"`
	}
	s, ok := p.ceremony(w, r, &in)
	if !ok {
		return
	}
	sig := registry.Signature{Officer: s.sub, ClientDataJSON: in.ClientDataJSON, AuthenticatorData: in.AuthenticatorData, Sig: in.Signature}
	done, err := p.Admin.SignAnchor(p.rp(), sig, admin.Event{At: p.Now(), Subject: s.sub, Source: r.Header.Get("X-Forwarded-For")}, p.Now())
	if err != nil {
		p.Log.Warn("anchor signature refused", "sub", s.sub, "err", err)
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if done {
		p.Log.Info("fleet anchored", "by", s.sub)
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed": true, "anchored": done})
}

// anchorView is the page's anchor section before the fleet is anchored.
type anchorView struct {
	Named          []officerRow
	TooFew         bool
	Hash, Until    string
	MeNamed, MeHas bool
	MeSign         bool
	Script         template.JS
}

type officerRow struct {
	Name, Passkey string
	Registered    bool
	Signed        bool
	Alarm         bool // the passkey under this name is not the signed-in person's
}

func (p *Page) anchorView(s session) *anchorView {
	if p.Admin == nil || p.Admin.Anchor() != "" {
		return nil
	}
	v := &anchorView{TooFew: len(p.Cfg.Officers) < registry.MinOfficers, MeNamed: p.named(s.name), Script: template.JS(script)}
	got := map[string]registry.Officer{}
	for _, o := range p.Admin.Candidates() {
		got[o.Name] = o
	}
	d, drafted, _ := p.draft()
	signed := map[string]bool{}
	for _, sg := range d.Signatures {
		signed[sg.Officer] = true
	}
	for _, name := range p.Cfg.Officers {
		o, ok := got[name]
		row := officerRow{Name: name, Registered: ok, Passkey: "not registered yet"}
		if ok {
			row.Passkey = "synced passkey"
			if o.DeviceBound {
				row.Passkey = "device-bound passkey"
			}
			row.Signed = drafted && signed[o.ID]
		}
		if name == s.name && ok && o.ID != s.sub { // registered under your name by another account
			row.Passkey, row.Alarm = "registered by a different account named "+name+": tell the other officers", true
		}
		if name == s.name {
			v.MeHas = ok && o.ID == s.sub
			v.MeSign = drafted && ok && o.ID == s.sub && !signed[o.ID]
		}
		v.Named = append(v.Named, row)
	}
	if drafted {
		v.Hash, v.Until = groups(d.Registry.Hash()[:32]), d.Statement.Expires.UTC().Format("2006-01-02 15:04Z")
	}
	return v
}

// groups writes a hash in groups of four, as people read it aloud.
func groups(h string) string {
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i:min(i+4, len(h))])
	}
	return b.String()
}

// script runs the two passkey steps. It writes only text (never markup), talks only to this page, and reloads it
// when a step is done. Allowed by its hash (scriptHash), so no other script can run on the page.
const script = `(()=>{
const dec=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const out=document.getElementById("anchor-msg");
const say=t=>{if(out)out.textContent=t};
async function post(path,body){
const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{}),credentials:"same-origin",cache:"no-store"});
let j={};try{j=await r.json()}catch(e){}
if(!r.ok)throw new Error(j.error||("the fleet answered "+r.status));
return j}
function step(id,run){
const b=document.getElementById(id);if(!b)return;
if(!window.PublicKeyCredential||!navigator.credentials){b.disabled=true;say("This browser cannot use passkeys: open the page in a current browser.");return}
b.addEventListener("click",async()=>{
b.disabled=true;say("Waiting for your passkey...");
try{await run();say("Done. Reloading...");location.reload()}
catch(e){say(e&&e.name==="NotAllowedError"?"The passkey prompt was cancelled or timed out: try again.":"Not done: "+(e&&e.message||e));b.disabled=false}})}
step("officer-register",async()=>{
const o=await post("/officer/begin");
o.challenge=dec(o.challenge);o.user.id=dec(o.user.id);
o.excludeCredentials=(o.excludeCredentials||[]).map(c=>({type:c.type,id:dec(c.id)}));
const c=await navigator.credentials.create({publicKey:o});
await post("/officer/finish",{client_data_json:enc(c.response.clientDataJSON),attestation_object:enc(c.response.attestationObject)})});
step("anchor-sign",async()=>{
const o=await post("/anchor/begin");
o.challenge=dec(o.challenge);
o.allowCredentials=o.allowCredentials.map(c=>({type:c.type,id:dec(c.id)}));
const a=await navigator.credentials.get({publicKey:o});
await post("/anchor/sign",{client_data_json:enc(a.response.clientDataJSON),authenticator_data:enc(a.response.authenticatorData),signature:enc(a.response.signature)})});
})();`

var scriptHash = func() string {
	h := sha256.Sum256([]byte(script))
	return "sha256-" + base64.StdEncoding.EncodeToString(h[:])
}()

// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"net/http"
	"slices"
	"time"

	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"relikey/fleet/internal/registry"
)

// Activation (decision 0026 points 15, 24, 32, 33): an officer selects presented slots, types for each at least 16
// characters of the fingerprint as read from the edge's screen and records who read it and how, and signs the
// activation with their officer passkey. The page builds the statement and checks the items before asking for the
// passkey; the store verifies the signature against the registry in force. Nothing is active before that signature.

// pendingActivation is an activation an officer is signing: the statement is fixed at begin, used once at sign.
type pendingActivation struct {
	a     enrol.Activation
	st    registry.Statement
	until time.Time
}

type activateItem struct {
	Slot    string `json:"slot"`
	Typed   string `json:"typed"`
	ReadBy  string `json:"read_by"`
	ReadHow string `json:"read_how"`
}

// officer is the signed-in person as an officer of the registry in force.
func (p *Page) officer(s session) (registry.Registry, registry.Officer, bool) {
	reg, ok := p.Admin.Current(p.Now())
	if !ok {
		return reg, registry.Officer{}, false
	}
	i := slices.IndexFunc(reg.Officers, func(o registry.Officer) bool { return o.ID == s.sub })
	if i < 0 {
		return reg, registry.Officer{}, false
	}
	return reg, reg.Officers[i], true
}

// activateBegin checks an activation and gives the officer the request to sign it with their own passkey.
func (p *Page) activateBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items []activateItem `json:"items"`
	}
	s, ok := p.step(w, r, &in, true)
	if !ok {
		return
	}
	reg, o, ok := p.officer(s)
	if !ok {
		fail(w, http.StatusForbidden, "only an officer approves an enrolment, with their officer passkey")
		return
	}
	slots := map[string]enrol.Slot{}
	for _, sl := range p.Admin.Slots() {
		slots[sl.ID] = sl
	}
	a := enrol.Activation{Fleet: reg.Fleet, Approver: o.ID}
	for _, it := range in.Items {
		fp := ""
		if sl, ok := slots[it.Slot]; ok && sl.Key != "" {
			fp = enrol.Fingerprint(sl.Key) // the statement covers the whole fingerprint the officer was shown
		}
		a.Items = append(a.Items, enrol.Item{Slot: it.Slot, Fingerprint: fp, Typed: it.Typed, ReadBy: it.ReadBy, ReadHow: it.ReadHow})
	}
	if err := p.Admin.CheckActivation(a, p.Now()); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	now := p.Now()
	st := registry.Statement{Kind: "activate", Fleet: reg.Fleet, Registry: reg.Version, Body: a.Hash(),
		Expires: now.Add(challengeTTL), Nonce: random()}
	p.mu.Lock()
	if p.activations == nil {
		p.activations = map[string]pendingActivation{}
	}
	prune(p.activations, func(x pendingActivation) bool { return !now.Before(x.until) }, func(x pendingActivation) time.Time { return x.until })
	p.activations[p.sessionID(r)] = pendingActivation{a: a, st: st, until: st.Expires}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":        b64.EncodeToString(st.Challenge()),
		"rpId":             p.rp().ID,
		"allowCredentials": []credDesc{{"public-key", o.CredentialID}},
		"userVerification": "required",
		"timeout":          ceremonyMS,
	})
}

// activateSign takes the officer's signature over the activation begun in this session; with it the slots are active.
func (p *Page) activateSign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientDataJSON    string `json:"client_data_json"`
		AuthenticatorData string `json:"authenticator_data"`
		Signature         string `json:"signature"`
	}
	s, ok := p.step(w, r, &in, true)
	if !ok {
		return
	}
	p.mu.Lock()
	pa, had := p.activations[p.sessionID(r)]
	delete(p.activations, p.sessionID(r)) // one use, whatever the outcome
	p.mu.Unlock()
	if !had || !p.Now().Before(pa.until) || pa.a.Approver != s.sub {
		fail(w, http.StatusBadRequest, "no activation is being signed in this session: start again")
		return
	}
	sig := registry.Signature{Officer: s.sub, ClientDataJSON: in.ClientDataJSON, AuthenticatorData: in.AuthenticatorData, Sig: in.Signature}
	ev := admin.Event{At: p.Now(), Subject: s.sub, Source: r.Header.Get("X-Forwarded-For")}
	out, err := p.Admin.Activate(p.rp(), pa.a, pa.st, sig, ev, p.Now())
	if err != nil {
		p.Log.Warn("activation refused", "sub", s.sub, "err", err)
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	names := make([]string, 0, len(out))
	for _, sl := range out {
		names = append(names, sl.Name)
	}
	p.Log.Info("edges enrolled", "by", s.sub, "edges", names)
	writeJSON(w, http.StatusOK, map[string]any{"active": names})
}

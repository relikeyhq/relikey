// SPDX-License-Identifier: EUPL-1.2

// Package registry is the fleet's officer registry (decision 0026 points 16, 21, 29, 30): who may approve, anchored at
// install and changed only by officers' passkey signatures over bound statements. Pure: no storage, no HTTP. Every
// check here is also meant to run outside the fleet server (point 20), so it depends on nothing the server holds
// beyond the statements and the registry chain themselves.
package registry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"
)

// StatementContext prefixes every statement hash: a passkey signature for ReliKey's fleet can never be read as
// another protocol's (point 21).
const StatementContext = "relikey-fleet-stmt-v1"

const (
	MinOfficers = 3              // a registry never has fewer (point 29)
	ChangeDelay = 48 * time.Hour // a change takes effect after this, unless break-glass (point 29)
)

// Officer is one approver: a passkey registered for fleet statements only, never for broker sign-in (point 21).
type Officer struct {
	ID           string `json:"id"`            // stable, e.g. the broker subject
	Name         string `json:"name"`          // shown to people
	CredentialID string `json:"credential_id"` // base64url
	PublicKey    string `json:"public_key"`    // base64url COSE key
	DeviceBound  bool   `json:"device_bound"`  // registered without backup eligibility (BE=0): not a synced passkey
}

// Registry is one version of the officer list. Version 1 is the anchor.
type Registry struct {
	Fleet    string    `json:"fleet"`
	Version  int64     `json:"version"`
	Previous string    `json:"previous"` // hex sha256 of the previous version's canonical bytes; empty for the anchor
	Officers []Officer `json:"officers"`
}

// Hash is the registry's identity in the chain: sha256 of its canonical JSON.
func (r Registry) Hash() string {
	b, _ := json.Marshal(r, json.Deterministic(true))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (r Registry) officer(id string) (Officer, bool) {
	i := slices.IndexFunc(r.Officers, func(o Officer) bool { return o.ID == id })
	if i < 0 {
		return Officer{}, false
	}
	return r.Officers[i], true
}

// Statement is what an officer's passkey signs, bound into the WebAuthn challenge (point 21).
type Statement struct {
	Kind     string    `json:"kind"`     // "registry", "activate", ...
	Fleet    string    `json:"fleet"`    // the fleet's id
	Registry int64     `json:"registry"` // the registry version it is judged under
	Body     string    `json:"body"`     // hex sha256 of what is approved (a registry's Hash, an activation's)
	Expires  time.Time `json:"expires"`
	Nonce    string    `json:"nonce"`
}

// Challenge is the bytes the passkey signs: sha256 of the context and the statement's canonical JSON.
func (s Statement) Challenge() []byte {
	b, _ := json.Marshal(s, json.Deterministic(true))
	sum := sha256.Sum256(append([]byte(StatementContext+"\n"), b...))
	return sum[:]
}

// Signature is one officer's WebAuthn assertion over a statement, kept whole as evidence (point 21).
type Signature struct {
	Officer           string `json:"officer"`
	ClientDataJSON    string `json:"client_data_json"`   // base64url
	AuthenticatorData string `json:"authenticator_data"` // base64url
	Sig               string `json:"signature"`          // base64url
}

// RP is the relying party statements are signed for: the fleet page's own name, nothing else.
type RP struct {
	ID     string // the rpId, e.g. fleet.example
	Origin string // https://fleet.example[:port]
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Verify checks one signature against an officer and a statement: a webauthn.get ceremony, the exact origin, this
// statement's challenge, the rpId hash, user verification, and the signature under the officer's key. It returns
// whether the authenticator reported its credential as backed up (BS) or backup-eligible (BE).
func (rp RP) Verify(sig Signature, o Officer, st Statement, now time.Time) (synced bool, err error) {
	if !now.Before(st.Expires) {
		return false, errors.New("the statement has expired")
	}
	cdj, err1 := b64(sig.ClientDataJSON)
	ad, err2 := b64(sig.AuthenticatorData)
	raw, err3 := b64(sig.Sig)
	key, err4 := b64(o.PublicKey)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return false, fmt.Errorf("a signature's fields are not base64url: %w", err)
	}
	flags, err := verifyAssertion(cdj, ad, raw, key, st.Challenge(), rp.ID, rp.Origin)
	if err != nil {
		return false, err
	}
	return flags&(flagBE|flagBS) != 0, nil
}

// Change is a new registry and the signatures that carry it.
type Change struct {
	Registry   Registry    `json:"registry"`
	Statement  Statement   `json:"statement"`
	Signatures []Signature `json:"signatures"`
	BreakGlass bool        `json:"break_glass"` // asks to skip the delay (point 29)
}

// Accepted is a verified registry version and when it takes effect.
type Accepted struct {
	Registry  Registry
	Effective time.Time
	// BreakGlass: the delay was waived; every officer is alarmed and it is reviewed after.
	BreakGlass bool
}

func (c Change) checkStatement(r Registry, judgedUnder int64) error {
	st := c.Statement
	switch {
	case st.Kind != "registry":
		return errors.New("the statement is not a registry change")
	case st.Fleet != r.Fleet:
		return errors.New("the statement is for another fleet")
	case st.Registry != judgedUnder:
		return fmt.Errorf("the statement is judged under registry %d, not %d", st.Registry, judgedUnder)
	case st.Body != r.Hash():
		return errors.New("the statement approves another registry")
	case st.Nonce == "":
		return errors.New("the statement carries no nonce")
	}
	return nil
}

func checkOfficers(r Registry) error {
	if len(r.Officers) < MinOfficers {
		return fmt.Errorf("a registry has at least %d officers (point 29)", MinOfficers)
	}
	seen, creds := map[string]bool{}, map[string]bool{}
	for _, o := range r.Officers {
		if o.ID == "" || o.CredentialID == "" || o.PublicKey == "" {
			return errors.New("an officer names an id, a credential and a key")
		}
		if seen[o.ID] || creds[o.CredentialID] {
			return fmt.Errorf("officer %s or its credential appears twice", o.ID)
		}
		seen[o.ID], creds[o.CredentialID] = true, true
	}
	return nil
}

// signers verifies every signature against the given registry's officers and returns them by officer, with
// whether each came from a device-bound credential (registered so, and not reporting backup now).
func signers(rp RP, sigs []Signature, under Registry, st Statement, now time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	for _, s := range sigs {
		o, ok := under.officer(s.Officer)
		if !ok {
			return nil, fmt.Errorf("%s is not an officer of registry %d", s.Officer, under.Version)
		}
		if _, dup := out[o.ID]; dup {
			return nil, fmt.Errorf("%s signed twice: two signatures come from two people", o.ID)
		}
		synced, err := rp.Verify(s, o, st, now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.ID, err)
		}
		out[o.ID] = o.DeviceBound && !synced
	}
	return out, nil
}

// Anchor verifies version 1: at least three officers, each of whom signed it, proving they hold their passkey; an
// installer alone cannot complete it (point 30).
func Anchor(rp RP, c Change, now time.Time) (Accepted, error) {
	r := c.Registry
	if r.Version != 1 || r.Previous != "" {
		return Accepted{}, errors.New("the anchor is version 1 with no previous")
	}
	if err := checkOfficers(r); err != nil {
		return Accepted{}, err
	}
	if err := c.checkStatement(r, 1); err != nil {
		return Accepted{}, err
	}
	signed, err := signers(rp, c.Signatures, r, c.Statement, now)
	if err != nil {
		return Accepted{}, err
	}
	for _, o := range r.Officers {
		if _, ok := signed[o.ID]; !ok {
			return Accepted{}, fmt.Errorf("officer %s has not signed the anchor: each proves their passkey", o.ID)
		}
	}
	return Accepted{Registry: r, Effective: now}, nil
}

// Apply verifies a change against the current registry (point 29): the next version naming the current one by hash;
// two signatures from distinct current officers, one of them device-bound; a majority of the current officers when
// anyone is removed; every added officer's own signature; at least three officers after; effective after 48 hours,
// or at once as break-glass with a majority including a device-bound signature.
func Apply(rp RP, cur Registry, c Change, now time.Time) (Accepted, error) {
	next := c.Registry
	switch {
	case next.Fleet != cur.Fleet:
		return Accepted{}, errors.New("a change for another fleet")
	case next.Version != cur.Version+1:
		return Accepted{}, fmt.Errorf("the next version is %d, not %d (an older registry cannot come back)", cur.Version+1, next.Version)
	case next.Previous != cur.Hash():
		return Accepted{}, errors.New("the change does not name the current registry as its previous")
	}
	if err := checkOfficers(next); err != nil {
		return Accepted{}, err
	}
	if err := c.checkStatement(next, cur.Version); err != nil {
		return Accepted{}, err
	}
	// Current officers sign under the current registry; added officers prove their own passkey.
	var curSigs, newSigs []Signature
	for _, s := range c.Signatures {
		if _, ok := cur.officer(s.Officer); ok {
			curSigs = append(curSigs, s)
		} else {
			newSigs = append(newSigs, s)
		}
	}
	old, err := signers(rp, curSigs, cur, c.Statement, now)
	if err != nil {
		return Accepted{}, err
	}
	added, err := signers(rp, newSigs, next, c.Statement, now)
	if err != nil {
		return Accepted{}, err
	}
	bound := slices.Contains(mapValues(old), true)
	majority := len(old)*2 > len(cur.Officers)
	switch {
	case len(old) < 2:
		return Accepted{}, errors.New("a change needs two current officers' signatures")
	case !bound:
		return Accepted{}, errors.New("one of the signatures must come from a device-bound passkey (not a synced one)")
	}
	for _, o := range cur.Officers {
		if _, kept := next.officer(o.ID); !kept && !majority {
			return Accepted{}, fmt.Errorf("removing %s needs a majority of the current officers", o.ID)
		}
	}
	for _, o := range next.Officers {
		if _, existing := cur.officer(o.ID); !existing {
			if _, ok := added[o.ID]; !ok {
				return Accepted{}, fmt.Errorf("the added officer %s has not signed: each proves their passkey", o.ID)
			}
		}
	}
	if c.BreakGlass {
		if !majority {
			return Accepted{}, errors.New("break-glass needs a majority of the current officers, one of them device-bound")
		}
		return Accepted{Registry: next, Effective: now, BreakGlass: true}, nil
	}
	return Accepted{Registry: next, Effective: now.Add(ChangeDelay)}, nil
}

func mapValues(m map[string]bool) []bool {
	out := make([]bool, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

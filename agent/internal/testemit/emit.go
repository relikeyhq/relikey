// SPDX-License-Identifier: EUPL-1.2

// Package testemit is a second emitter of the edge protocol, for tests only (decision 0017 point 6): it turns plain
// grants into a signed bundle and an officer-sealed ceiling from the published format alone (the edge interface,
// docs/keyclerk-edge-interface.md), with no code from KeyClerk and none from the agent's verifier (package kcedge):
// its own canonical encoding, its own sealing. The tests check that the agent's verifier accepts what it emits and
// refuses each way of breaking the profile. Nothing here ships: no binary imports it.
package testemit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

const (
	bundleFormat  = "kc-edge-bundle-v3"
	ceilingFormat = "kc-edge-ceiling-v2"
)

// Grant is what a general IGA knows: a person may reach a target with a role, in a window.
type Grant struct {
	ID, Person, Username, Email, Target, Role, Class string
	From, Until                                      time.Time
}

// Emitter holds the residue an IGA does not have (decision 0017 point 7): the edge, the keys, the serials, the
// horizons and the ceiling.
type Emitter struct {
	Edge          string
	BundleKey     ed25519.PrivateKey
	OfficerKey    ed25519.PrivateKey // the officer's, never the bundle key (decision 0017 point 3)
	Serial        int64
	CeilingSerial int64
	Horizons      map[string]int64 // hours per class
	Persons       []string         // the ceiling: who may be admitted at this edge
	Targets       []string
	MaxLease      int64    // hours
	MaxOffline    int64    // hours
	Governed      []string // nil: no catalogue; empty: none governed
}

// Canonical is the signed form: members sorted by name, no whitespace, strings as UTF-8 with only the quote, the
// backslash and control characters escaped. encoding/json sorts map keys and writes integers exactly; HTML escaping
// is switched off.
func Canonical(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func hexPub(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

func keyID(pubHex string) string {
	raw, _ := hex.DecodeString(pubHex)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

// Seal signs obj as format: the format tag and key id go inside the signed bytes.
func Seal(key ed25519.PrivateKey, obj map[string]any, format string) map[string]any {
	pub := hexPub(key)
	body := map[string]any{}
	for k, v := range obj {
		body[k] = v
	}
	body["format"], body["key_id"] = format, keyID(pub)
	raw := Canonical(body)
	return map[string]any{"bytes": base64.StdEncoding.EncodeToString(raw),
		"signature": hex.EncodeToString(ed25519.Sign(key, raw)), "key": pub, "key_id": keyID(pub)}
}

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Ceiling is the officer's sealed ceiling for this edge.
func (e *Emitter) Ceiling(signedAt time.Time) map[string]any {
	return Seal(e.OfficerKey, map[string]any{"edge": e.Edge, "serial": e.CeilingSerial,
		"persons": orEmpty(e.Persons), "roles": []string{}, "targets": orEmpty(e.Targets),
		"classes": []string{"low", "elevated", "privileged"}, "max_lease_hours": e.MaxLease,
		"max_offline_hours": e.MaxOffline, "profile": "basic", "remote_reach": "off", "ports": []int{22},
		"signed_at": iso(signedAt)}, ceilingFormat)
}

// Bundle is the signed bundle: the grants as leases, the revoked ids, the ceiling as the officer sealed it.
func (e *Emitter) Bundle(issued time.Time, grants []Grant, revoked []string) map[string]any {
	leases := []any{}
	for _, g := range grants {
		leases = append(leases, map[string]any{"lease_id": g.ID, "person": g.Person, "username": g.Username,
			"email": g.Email, "target": g.Target, "role": g.Role, "roles": []string{}, "class": g.Class,
			"from": iso(g.From), "until": iso(g.Until)})
	}
	b := map[string]any{"edge": e.Edge, "serial": e.Serial, "issued": iso(issued), "horizons": e.Horizons,
		"leases": leases, "visit_leases": []any{}, "revoked": orEmpty(revoked), "ceiling": e.Ceiling(issued.Add(-time.Hour)),
		"policy": map[string]any{"modules": map[string]any{}, "release": nil, "entrypoints": []any{}}}
	if e.Governed != nil {
		gr := []any{}
		for _, r := range e.Governed {
			gr = append(gr, map[string]any{"displayName": r})
		}
		b["governed_roles"] = gr
	}
	return Seal(e.BundleKey, b, bundleFormat)
}

// Pins are what the edge pinned at enrolment, as hex.
func (e *Emitter) Pins() (edge, bundleKey, officerKey string) {
	return e.Edge, hexPub(e.BundleKey), hexPub(e.OfficerKey)
}

// Reserialised returns the sealed object with its signed bytes rewritten as indented JSON: the same members, other
// bytes, the signature over the originals. A verifier that re-encodes before checking would accept it.
func Reserialised(sealed map[string]any) map[string]any {
	raw, _ := base64.StdEncoding.DecodeString(sealed["bytes"].(string))
	var v any
	_ = json.Unmarshal(raw, &v)
	pretty, _ := json.MarshalIndent(v, "", " ")
	out := map[string]any{}
	for k, x := range sealed {
		out[k] = x
	}
	out["bytes"] = base64.StdEncoding.EncodeToString(pretty)
	return out
}

// Key is a test key from a label.
func Key(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("testemit:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

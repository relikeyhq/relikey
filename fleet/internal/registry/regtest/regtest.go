// SPDX-License-Identifier: EUPL-1.2

// Package regtest is a software passkey for tests: it answers webauthn.create and webauthn.get as a browser and an
// authenticator would, with switches to make each answer wrong in one way. Tests only; nothing else imports it.
package regtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"

	"github.com/fxamacker/cbor/v2"

	"relikey/fleet/internal/registry"
)

const (
	FlagUP = 1 << 0
	FlagUV = 1 << 2
	FlagBE = 1 << 3
	FlagBS = 1 << 4
	FlagAT = 1 << 6
)

// Authenticator is one passkey.
type Authenticator struct {
	Alg    string // es256, eddsa, rs256
	Synced bool   // backup eligible and backed up
	Cred   []byte // the credential id
	ec     *ecdsa.PrivateKey
	ed     ed25519.PrivateKey
	rsa    *rsa.PrivateKey
	cose   []byte
}

// New makes a passkey of the given kind.
func New(alg string, synced bool) *Authenticator {
	a := &Authenticator{Alg: alg, Synced: synced, Cred: make([]byte, 32)}
	_, _ = rand.Read(a.Cred)
	switch alg {
	case "es256":
		a.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "eddsa":
		_, a.ed, _ = ed25519.GenerateKey(rand.Reader)
	case "rs256":
		a.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	a.cose = a.encode()
	return a
}

// COSE is the passkey's public key as a COSE key, encoded once (core deterministic CBOR).
func (a *Authenticator) COSE() []byte { return a.cose }

func (a *Authenticator) encode() []byte {
	var m map[int]any
	switch a.Alg {
	case "es256":
		raw, _ := a.ec.PublicKey.Bytes()
		m = map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:]}
	case "eddsa":
		m = map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(a.ed.Public().(ed25519.PublicKey))}
	case "rs256":
		m = map[int]any{1: 3, 3: -257, -1: a.rsa.N.Bytes(), -2: []byte{1, 0, 1}}
	}
	em, _ := cbor.CoreDetEncOptions().EncMode()
	b, _ := em.Marshal(m)
	return b
}

// Officer is the passkey as a registry entry.
func (a *Authenticator) Officer(id, name string) registry.Officer {
	e := base64.RawURLEncoding.EncodeToString
	return registry.Officer{ID: id, Name: name, CredentialID: e(a.Cred), PublicKey: e(a.COSE()), DeviceBound: !a.Synced}
}

// Tweak makes an answer wrong in one way; the zero value is a correct answer.
type Tweak struct {
	Type, Origin, RPID string
	Flags              byte // replaces the flags when non-zero
	Challenge          []byte
	CrossOrigin        bool
	Cred               []byte // replaces the credential id (create)
	Key                []byte // replaces the COSE key (create)
	Fmt                string // replaces "none" (create)
}

func (a *Authenticator) clientData(typ string, rp registry.RP, challenge []byte, tw Tweak) []byte {
	if tw.Type != "" {
		typ = tw.Type
	}
	origin := rp.Origin
	if tw.Origin != "" {
		origin = tw.Origin
	}
	if tw.Challenge != nil {
		challenge = tw.Challenge
	}
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin": origin, "crossOrigin": tw.CrossOrigin})
	return cd
}

func (a *Authenticator) flags(base byte, tw Tweak) byte {
	if tw.Flags != 0 {
		return tw.Flags
	}
	f := base | FlagUP | FlagUV
	if a.Synced {
		f |= FlagBE | FlagBS
	}
	return f
}

func (a *Authenticator) authHead(rp registry.RP, flags byte, tw Tweak) []byte {
	id := rp.ID
	if tw.RPID != "" {
		id = tw.RPID
	}
	h := sha256.Sum256([]byte(id))
	return append(append(h[:], flags), 0, 0, 0, 1)
}

// Create answers navigator.credentials.create: client data JSON and an attestation object (format none).
func (a *Authenticator) Create(rp registry.RP, challenge []byte, tw Tweak) (clientDataJSON, attestationObject []byte) {
	cred, key, fmt := a.Cred, a.COSE(), "none"
	if tw.Cred != nil {
		cred = tw.Cred
	}
	if tw.Key != nil {
		key = tw.Key
	}
	if tw.Fmt != "" {
		fmt = tw.Fmt
	}
	ad := a.authHead(rp, a.flags(FlagAT, tw), tw)
	ad = append(ad, make([]byte, 16)...) // aaguid
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(cred)))
	ad = append(append(ad, cred...), key...)
	att, _ := cbor.Marshal(map[string]any{"fmt": fmt, "attStmt": map[string]any{}, "authData": ad})
	return a.clientData("webauthn.create", rp, challenge, tw), att
}

// Get answers navigator.credentials.get over a challenge.
func (a *Authenticator) Get(rp registry.RP, challenge []byte, tw Tweak) (clientDataJSON, authData, sig []byte) {
	cd := a.clientData("webauthn.get", rp, challenge, tw)
	ad := a.authHead(rp, a.flags(0, tw), tw)
	h := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), h[:]...)
	switch a.Alg {
	case "es256":
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, a.ec, d[:])
	case "eddsa":
		sig = ed25519.Sign(a.ed, msg)
	case "rs256":
		d := sha256.Sum256(msg)
		sig, _ = rsa.SignPKCS1v15(rand.Reader, a.rsa, crypto.SHA256, d[:])
	}
	return cd, ad, sig
}

// Sign is Get as a registry signature by officer id.
func (a *Authenticator) Sign(rp registry.RP, officer string, st registry.Statement, tw Tweak) registry.Signature {
	cd, ad, sig := a.Get(rp, st.Challenge(), tw)
	e := base64.RawURLEncoding.EncodeToString
	return registry.Signature{Officer: officer, ClientDataJSON: e(cd), AuthenticatorData: e(ad), Sig: e(sig)}
}

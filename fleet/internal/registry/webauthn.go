// SPDX-License-Identifier: EUPL-1.2

package registry

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// A WebAuthn assertion check, the part the fleet needs and nothing more (W3C WebAuthn Level 3, sections 6.1 and 7.2):
// the client data, the authenticator data and the signature under a COSE key of the three kinds passkeys use.

const (
	flagUP = 1 << 0 // user present
	flagUV = 1 << 2 // user verified
	flagBE = 1 << 3 // backup eligible
	flagBS = 1 << 4 // backup state
	flagAT = 1 << 6 // attested credential data follows (registration)
)

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func checkClientData(raw []byte, ceremony string, challenge []byte, origin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("client data: %w", err)
	}
	switch {
	case cd.Type != ceremony:
		return fmt.Errorf("client data: a %s ceremony, not %s", cd.Type, ceremony)
	case subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(base64.RawURLEncoding.EncodeToString(challenge))) != 1:
		return errors.New("client data: signed for another statement (challenge)")
	case cd.Origin != origin:
		return fmt.Errorf("client data: signed on %q, not %q", cd.Origin, origin)
	case cd.CrossOrigin:
		return errors.New("client data: signed in a cross-origin frame")
	}
	return nil
}

type authData struct {
	flags   byte
	counter uint32
	credID  []byte
	coseKey []byte // registration only
}

func parseAuthData(raw []byte, rpID string) (authData, error) {
	if len(raw) < 37 {
		return authData{}, errors.New("authenticator data: too short")
	}
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(raw[:32], want[:]) != 1 {
		return authData{}, errors.New("authenticator data: for another relying party (rpId)")
	}
	a := authData{flags: raw[32], counter: binary.BigEndian.Uint32(raw[33:37])}
	if a.flags&flagUP == 0 || a.flags&flagUV == 0 {
		return authData{}, errors.New("authenticator data: the user was not present and verified (UP and UV)")
	}
	if a.flags&flagAT != 0 { // aaguid(16) | idLen(2) | credID | COSE key (CBOR)
		rest := raw[37:]
		if len(rest) < 18 {
			return authData{}, errors.New("authenticator data: truncated credential data")
		}
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		if len(rest) < 18+n {
			return authData{}, errors.New("authenticator data: truncated credential id")
		}
		a.credID = rest[18 : 18+n]
		var key cbor.RawMessage
		if _, err := cbor.UnmarshalFirst(rest[18+n:], &key); err != nil {
			return authData{}, fmt.Errorf("authenticator data: the credential key: %w", err)
		}
		a.coseKey = key
	}
	return a, nil
}

// COSE key parameters (RFC 9052/9053) for ES256 (-7), EdDSA (-8) and RS256 (-257).
type coseKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Alg int64  `cbor:"3,keyasint"`
	Crv int64  `cbor:"-1,keyasint,omitempty"` // EC2, OKP; for RSA this label is n
	X   []byte `cbor:"-2,keyasint,omitempty"` // EC2 x, OKP x; for RSA e
	Y   []byte `cbor:"-3,keyasint,omitempty"`
}

type rsaCose struct {
	Kty int64  `cbor:"1,keyasint"`
	Alg int64  `cbor:"3,keyasint"`
	N   []byte `cbor:"-1,keyasint"`
	E   []byte `cbor:"-2,keyasint"`
}

// publicKey is a parsed COSE key of a kind ReliKey takes.
type publicKey func(data, sig []byte) error

func parseCOSE(key []byte) (publicKey, error) {
	var k coseKey
	if err := cbor.Unmarshal(key, &k); err != nil {
		var r rsaCose
		if err2 := cbor.Unmarshal(key, &r); err2 != nil || r.Kty != 3 || r.Alg != -257 {
			return nil, fmt.Errorf("the key is not a COSE key ReliKey takes: %w", err)
		}
		return rsaKey(r)
	}
	switch {
	case k.Kty == 2 && k.Alg == -7 && k.Crv == 1: // EC2, ES256, P-256
		if len(k.X) != 32 || len(k.Y) != 32 {
			return nil, errors.New("a P-256 key has 32-byte coordinates")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, k.X...), k.Y...)) // checks the curve
		if err != nil {
			return nil, fmt.Errorf("the key is not on P-256: %w", err)
		}
		return func(data, sig []byte) error {
			h := sha256.Sum256(data)
			if !ecdsa.VerifyASN1(pub, h[:], sig) {
				return errors.New("the signature does not verify")
			}
			return nil
		}, nil
	case k.Kty == 1 && k.Alg == -8 && k.Crv == 6 && len(k.X) == ed25519.PublicKeySize: // OKP, EdDSA, Ed25519
		pub := ed25519.PublicKey(k.X)
		return func(data, sig []byte) error {
			if !ed25519.Verify(pub, data, sig) {
				return errors.New("the signature does not verify")
			}
			return nil
		}, nil
	case k.Kty == 3 && k.Alg == -257:
		var r rsaCose
		if err := cbor.Unmarshal(key, &r); err != nil {
			return nil, err
		}
		return rsaKey(r)
	}
	return nil, fmt.Errorf("a key of type %d, algorithm %d: ReliKey takes ES256, EdDSA and RS256", k.Kty, k.Alg)
}

func verifyCOSE(key []byte, data, sig []byte) error {
	pub, err := parseCOSE(key)
	if err != nil {
		return err
	}
	return pub(data, sig)
}

func rsaKey(r rsaCose) (publicKey, error) {
	e := new(big.Int).SetBytes(r.E)
	if !e.IsInt64() || e.Int64() < 3 || len(r.N) < 256 {
		return nil, errors.New("an RSA key of at least 2048 bits with a usual exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(r.N), E: int(e.Int64())}
	return func(data, sig []byte) error {
		h := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return errors.New("the signature does not verify")
		}
		return nil
	}, nil
}

// verifyAssertion checks an assertion: webauthn.get, the challenge, the origin, the rpId, UP and UV, and the
// signature over authenticatorData || sha256(clientDataJSON). It returns the authenticator flags.
func verifyAssertion(cdj, ad, sig, key, challenge []byte, rpID, origin string) (byte, error) {
	if err := checkClientData(cdj, "webauthn.get", challenge, origin); err != nil {
		return 0, err
	}
	a, err := parseAuthData(ad, rpID)
	if err != nil {
		return 0, err
	}
	h := sha256.Sum256(cdj)
	if err := verifyCOSE(key, append(append([]byte{}, ad...), h[:]...), sig); err != nil {
		return 0, err
	}
	return a.flags, nil
}

// Credential is a passkey a webauthn.create ceremony registered.
type Credential struct {
	ID          []byte
	Key         []byte // the COSE key, as the authenticator gave it
	DeviceBound bool   // not backup eligible (BE=0): not a synced passkey
}

type attestation struct {
	Fmt      string          `cbor:"fmt"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
	AuthData []byte          `cbor:"authData"`
}

// MaxCredentialID is the longest credential id WebAuthn allows.
const MaxCredentialID = 1023

// VerifyRegistration checks a webauthn.create answer (W3C WebAuthn Level 3, section 7.1): the ceremony, this
// challenge, the exact origin, not in a cross-origin frame, the rpId, UP and UV, and a credential key of a kind
// ReliKey takes. The attestation statement is neither trusted nor checked: an officer is admitted by the officers'
// signatures (the anchor, or two officers), never by an authenticator vendor's certificate.
func (rp RP) VerifyRegistration(clientDataJSON, attestationObject, challenge []byte) (Credential, error) {
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, rp.Origin); err != nil {
		return Credential{}, err
	}
	var att attestation
	if err := cbor.Unmarshal(attestationObject, &att); err != nil {
		return Credential{}, fmt.Errorf("attestation object: %w", err)
	}
	a, err := parseAuthData(att.AuthData, rp.ID)
	if err != nil {
		return Credential{}, err
	}
	switch {
	case a.flags&flagAT == 0 || a.coseKey == nil:
		return Credential{}, errors.New("authenticator data: no credential in it")
	case len(a.credID) < 16 || len(a.credID) > MaxCredentialID:
		return Credential{}, fmt.Errorf("a credential id of %d bytes: WebAuthn's are 16 to %d", len(a.credID), MaxCredentialID)
	case a.flags&flagBS != 0 && a.flags&flagBE == 0:
		return Credential{}, errors.New("authenticator data: backed up but not backup eligible")
	}
	if _, err := parseCOSE(a.coseKey); err != nil {
		return Credential{}, err
	}
	return Credential{ID: bytes.Clone(a.credID), Key: bytes.Clone(a.coseKey), DeviceBound: a.flags&flagBE == 0}, nil
}

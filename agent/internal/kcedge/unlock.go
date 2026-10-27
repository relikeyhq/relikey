// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// UnlockContext is the phoned-unlock scheme (kc-unlock-v2, KeyClerk 0.23.0): P-256, so
// a node's unlock key can live in its TPM (ReliKey R-19). kc-unlock-v1 (X25519) is gone.
const UnlockContext = "kc-unlock-v2"

var (
	unlockPublicRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{87}$`)
	unlockPrivateRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// UnlockPrivate reads a software P-256 unlock key from its 32-byte scalar in hex (a
// node without a TPM; keyclerk.edge.unlock_private).
func UnlockPrivate(scalarHex string) (*ecdh.PrivateKey, error) {
	s := strings.TrimSpace(scalarHex)
	if !unlockPrivateRe.MatchString(s) {
		return nil, errors.New("a P-256 private key is its scalar, 64 lower-case hex characters")
	}
	b, _ := hex.DecodeString(s)
	return ecdh.P256().NewPrivateKey(b)
}

// UnlockPublicString is the public half as KeyClerk writes it: the uncompressed SEC1
// point (65 bytes, 04 x y), base64url without padding.
func UnlockPublicString(k *ecdh.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// LoadUnlockPublic reads an unlock public key: P-256, uncompressed, canonical
// base64url without padding, a point on the curve (keyclerk.edge.load_unlock_public).
func LoadUnlockPublic(s string) (*ecdh.PublicKey, error) {
	if !unlockPublicRe.MatchString(s) {
		return nil, errors.New("an unlock key is a P-256 point, 65 bytes uncompressed, base64url without padding (kc-unlock-v2)")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s || len(raw) != 65 || raw[0] != 4 {
		return nil, errors.New("an unlock key is an uncompressed P-256 point (04 x y), canonical base64url")
	}
	k, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("an unlock key is a point on P-256")
	}
	return k, nil
}

// UnlockSecret is the secret the desk and a node each compute from their own P-256 key
// and the other's public key; nothing secret crosses the network (ReliKey C-08). It
// binds the edge, the node (its enrolment key id) and both public keys.
func UnlockSecret(own *ecdh.PrivateKey, deskPublic, nodePublic, edge, nodeKeyID string) ([]byte, error) {
	var peer string
	switch UnlockPublicString(own) {
	case deskPublic:
		peer = nodePublic
	case nodePublic:
		peer = deskPublic
	default:
		return nil, errors.New("the own key is neither the desk's nor the node's unlock key")
	}
	pk, err := LoadUnlockPublic(peer)
	if err != nil {
		return nil, err
	}
	z, err := own.ECDH(pk) // the x coordinate, as TPM2_ECDH_ZGen gives it
	if err != nil {
		return nil, err
	}
	info := strings.Join([]string{UnlockContext, edge, nodeKeyID, deskPublic, nodePublic}, "|")
	return hkdf.Key(sha256.New, z, nil, info, 32)
}

// UnlockCode is the 10-character code an approver reads over the phone; the node
// recomputes it and compares. No field may be empty or hold a | or a line break.
func UnlockCode(secret []byte, edge, nodeKeyID, person, fingerprint, target, nonce string, minutes int) (string, error) {
	fields := []string{UnlockContext, edge, nodeKeyID, person, fingerprint, target, nonce, strconv.Itoa(minutes)}
	for _, f := range fields {
		if f == "" || strings.ContainsAny(f, "|\r\n") {
			return "", errors.New("an unlock field is non-empty text without | or a line break")
		}
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strings.Join(fields, "|")))
	return base32.StdEncoding.EncodeToString(m.Sum(nil))[:10], nil
}

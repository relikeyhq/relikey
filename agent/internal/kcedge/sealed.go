// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Sealed is a signed object on the wire: exactly {"bytes": base64 canonical JSON,
// "signature": hex, "key": hex, "key_id"} (keyclerk.edge.seal, amendment 0014d).
type Sealed struct {
	Bytes     string `json:"bytes"`
	Signature string `json:"signature"`
	Key       string `json:"key"`
	KeyID     string `json:"key_id"`
}

var (
	hexKey = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexSig = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// PublicKey parses a pinned Ed25519 key: 64 lower-case hex characters, as
// keyclerk.edge.load_public demands. The length check also keeps ed25519.Verify
// from panicking.
func PublicKey(hexkey string) (ed25519.PublicKey, error) {
	if !hexKey.MatchString(hexkey) {
		return nil, errors.New("an Ed25519 public key is 64 lower-case hex characters")
	}
	k, _ := hex.DecodeString(hexkey)
	return ed25519.PublicKey(k), nil
}

// KeyID is the first 16 hex characters of sha256 of the key (keyclerk.edge.key_id).
func KeyID(hexkey string) string {
	k, _ := hex.DecodeString(hexkey)
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:])[:16]
}

// verifyHex checks an Ed25519 signature given as 128 lower-case hex characters.
// Python's bytes.fromhex also takes upper case and spaces; this side is stricter.
func verifyHex(key ed25519.PublicKey, msg []byte, sig string) bool {
	if !hexSig.MatchString(sig) {
		return false
	}
	s, _ := hex.DecodeString(sig)
	return ed25519.Verify(key, msg, s)
}

// SealedFrom reads a sealed object out of parsed JSON: exactly the four members,
// each a string (keyclerk.edge.unseal refuses extra members since 0.23.0).
func SealedFrom(v Value) (Sealed, error) {
	o, ok := v.(Object)
	if !ok || !sameKeys(o, []string{"bytes", "key", "key_id", "signature"}) {
		return Sealed{}, errors.New("a sealed object is exactly {bytes, signature, key, key_id}")
	}
	var s Sealed
	for k, dst := range map[string]*string{"bytes": &s.Bytes, "signature": &s.Signature, "key": &s.Key, "key_id": &s.KeyID} {
		str, ok := o[k].(string)
		if !ok {
			return Sealed{}, errors.New("a sealed object is {bytes: base64, signature: 128 lower-case hex, key, key_id}")
		}
		*dst = str
	}
	return s, nil
}

// rawBytes decodes signed bytes from their base64, which must be canonical: padded,
// no trailing bits and no line breaks (Go's decoder skips \r and \n even in strict
// mode, so the re-encoding is compared, as keyclerk.edge._raw does; KC-8).
func rawBytes(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != b64 {
		return nil, errors.New("bytes: not canonical base64 (padding, trailing bits or line breaks)")
	}
	return raw, nil
}

// parseSigned is keyclerk.edge._parse: canonical JSON, integers 0..2^53-1, an object.
func parseSigned(raw []byte) (Object, error) {
	v, err := CheckCanonical(raw)
	if err != nil {
		return nil, err
	}
	if err := checkIntegers(v); err != nil {
		return nil, err
	}
	obj, ok := v.(Object)
	if !ok {
		return nil, errors.New("the signed bytes hold an object")
	}
	return obj, nil
}

// Unseal returns the object inside signed bytes and the bytes themselves, in the
// reference order: the pinned key, the signature over the decoded bytes, the bytes
// canonical, then the format and the key id inside.
func Unseal(s Sealed, pinnedHex, format string) (Object, []byte, error) {
	if s.Key != pinnedHex || s.KeyID != KeyID(pinnedHex) {
		return nil, nil, errors.New("a wrong signer: not the pinned key")
	}
	key, err := PublicKey(pinnedHex)
	if err != nil {
		return nil, nil, err
	}
	raw, err := rawBytes(s.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !verifyHex(key, raw, s.Signature) {
		return nil, nil, errors.New("a wrong signer: the signature does not verify over the bytes")
	}
	obj, err := parseSigned(raw)
	if err != nil {
		return nil, nil, err
	}
	if obj["format"] != format || obj["key_id"] != KeyID(pinnedHex) {
		return nil, nil, fmt.Errorf("not a %s signed by the pinned key", format)
	}
	return obj, raw, nil
}

// UnsealValue is Unseal for a sealed object still in parsed JSON (inside a bundle):
// its members are checked first.
func UnsealValue(v Value, pinnedHex, format string) (Object, []byte, error) {
	s, err := SealedFrom(v)
	if err != nil {
		return nil, nil, err
	}
	return Unseal(s, pinnedHex, format)
}

// OfficerFormat is the statement the officer and each node of an edge sign over the
// same bytes (kc-edge-officer-v2, amendment 0014d).
const OfficerFormat = "kc-edge-officer-v2"

// Signature is one signer's entry in a multi-signed object.
type Signature struct {
	Key       string `json:"key"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// MultiSigned is {"bytes": base64 canonical JSON, "signatures": [...]}.
type MultiSigned struct {
	Bytes      string      `json:"bytes"`
	Signatures []Signature `json:"signatures"`
}

// UnsealMulti is keyclerk.edge.unseal_multi: signed by exactly the required keys
// (each once, with its own key id, no other signature), canonical base64 and JSON,
// the format. v is the multi-signed object as parsed JSON.
func UnsealMulti(v Value, required []string, format string) (Object, error) {
	o, ok := v.(Object)
	if !ok || !sameKeys(o, []string{"bytes", "signatures"}) {
		return nil, errors.New("a multi-signed object is exactly {bytes, signatures}")
	}
	list, ok := o["signatures"].([]Value)
	if !ok {
		return nil, errors.New("signatures: a list of {key, key_id, signature}")
	}
	sigs := make([]Signature, 0, len(list))
	for _, e := range list {
		so, ok := e.(Object)
		if !ok || !sameKeys(so, []string{"key", "key_id", "signature"}) {
			return nil, errors.New("signatures: a list of {key, key_id, signature}")
		}
		k, ok1 := so["key"].(string)
		id, ok2 := so["key_id"].(string)
		sig, ok3 := so["signature"].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("signatures: key, key_id and signature are text")
		}
		sigs = append(sigs, Signature{Key: k, KeyID: id, Signature: sig})
	}
	keys := make([]string, len(sigs))
	for i, s := range sigs {
		keys[i] = s.Key
	}
	if len(slices.Compact(slices.Sorted(slices.Values(keys)))) != len(keys) {
		return nil, errors.New("a key signs once")
	}
	need := slices.Compact(slices.Sorted(slices.Values(required)))
	if !slices.Equal(slices.Sorted(slices.Values(keys)), need) {
		return nil, fmt.Errorf("signed by exactly %d keys", len(need))
	}
	b64, ok := o["bytes"].(string)
	if !ok {
		return nil, errors.New("bytes: base64 text")
	}
	raw, err := rawBytes(b64)
	if err != nil {
		return nil, err
	}
	for _, s := range sigs {
		if s.KeyID != KeyID(s.Key) {
			return nil, fmt.Errorf("the key_id of %.16s is not its own", s.Key)
		}
		key, err := PublicKey(s.Key)
		if err != nil || !verifyHex(key, raw, s.Signature) {
			return nil, fmt.Errorf("the signature of key %s does not verify over the bytes", s.KeyID)
		}
	}
	obj, err := parseSigned(raw)
	if err != nil {
		return nil, err
	}
	if obj["format"] != format {
		return nil, fmt.Errorf("not a %s", format)
	}
	return obj, nil
}

// Cosign adds this key's signature to a multi-signed object over its exact bytes,
// replacing an earlier signature by the same key (keyclerk.edge.cosign). The bytes
// must already be a canonical kc-edge-officer-v2: the edge never re-serialises.
func Cosign(m MultiSigned, priv ed25519.PrivateKey) (MultiSigned, error) {
	raw, err := rawBytes(m.Bytes)
	if err != nil {
		return MultiSigned{}, err
	}
	obj, err := parseSigned(raw)
	if err != nil {
		return MultiSigned{}, err
	}
	if obj["format"] != OfficerFormat {
		return MultiSigned{}, fmt.Errorf("not a %s", OfficerFormat)
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	out := MultiSigned{Bytes: m.Bytes}
	for _, s := range m.Signatures {
		if s.Key != pub {
			out.Signatures = append(out.Signatures, s)
		}
	}
	out.Signatures = append(out.Signatures, Signature{Key: pub, KeyID: KeyID(pub), Signature: hex.EncodeToString(ed25519.Sign(priv, raw))})
	slices.SortFunc(out.Signatures, func(a, b Signature) int {
		switch {
		case a.Key < b.Key:
			return -1
		case a.Key > b.Key:
			return 1
		}
		return 0
	})
	return out, nil
}

// EndedFormat is the desk's notice that an edge was ended, bound to the enrolment
// keys it ends (kc-edge-ended-v2, ReliKey AG-18).
const EndedFormat = "kc-edge-ended-v2"

// VerifyEnded is keyclerk.edge.verify_ended: sealed with the pinned bundle key, for
// this edge, naming this node's enrolment key, so a captured notice never ends a
// later enrolment. After it, nothing is live on the edge again.
func VerifyEnded(s Sealed, pins Pins, ownEnrolmentKey string) (reason string, err error) {
	obj, _, err := Unseal(s, pins.BundleKey, EndedFormat)
	if err != nil {
		return "", err
	}
	if t, ok := obj["ended"].(string); !ok {
		return "", errors.New("ended: a UTC time")
	} else if _, err := ParseTime(t); err != nil {
		return "", err
	}
	var errs []string
	if obj["edge"] != pins.Edge {
		errs = append(errs, "an ended notice for another edge")
	}
	keys, _ := obj["enrolment_keys"].([]Value)
	if !slices.Contains(keys, Value(KeyID(ownEnrolmentKey))) {
		errs = append(errs, "an ended notice for other enrolment keys: not this node")
	}
	if len(errs) > 0 {
		return "", errors.New(errorList(errs))
	}
	reason, _ = obj["reason"].(string)
	return reason, nil
}

// maxSafe is 2^53-1: every integer in a signed object lies in 0..maxSafe, so every
// language reads it the same (KeyClerk 0.22.0 onwards, KC-5).
const maxSafe = 1<<53 - 1

func checkIntegers(v Value) error {
	switch x := v.(type) {
	case Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil || n < 0 || n > maxSafe {
			return fmt.Errorf("the integer %s is outside 0 to 2^53-1", x)
		}
	case []Value:
		for _, e := range x {
			if err := checkIntegers(e); err != nil {
				return err
			}
		}
	case Object:
		for _, e := range x {
			if err := checkIntegers(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// EmailFormat is the desk's answer to an edge's own e-mail request (edge protocol 1.3): the address leaves the
// bundle, and the agent fetches it to set the gateway's SSO credential, keeping it nowhere.
const EmailFormat = "kc-edge-email-v1"

// MaxEmail is the longest address an answer may carry.
const MaxEmail = 320

// VerifyEmail is keyclerk.edge.verify_email: sealed with the pinned bundle key, for this edge and this lease,
// answering this request (nonce: an answer to another request is a replay). has is false when the broker holds no
// verified address for that person (email null).
func VerifyEmail(s Sealed, pins Pins, leaseID, nonce string) (email string, has bool, err error) {
	obj, _, err := Unseal(s, pins.BundleKey, EmailFormat)
	if err != nil {
		return "", false, err
	}
	if t, ok := obj["issued"].(string); !ok {
		return "", false, errors.New("issued: a UTC time")
	} else if _, err := ParseTime(t); err != nil {
		return "", false, err
	}
	var errs []string
	if obj["edge"] != pins.Edge {
		errs = append(errs, "an answer for another edge")
	}
	if obj["lease_id"] != leaseID {
		errs = append(errs, "an answer for another lease")
	}
	if obj["nonce"] != nonce {
		errs = append(errs, "an answer to another request: replayed")
	}
	if _, ok := obj["person"].(string); !ok {
		errs = append(errs, "an answer names its person")
	}
	switch e := obj["email"].(type) {
	case nil:
	case string:
		if len(e) < 3 || len(e) > MaxEmail || !strings.Contains(e, "@") {
			errs = append(errs, "an address is text with an @, at most 320 characters, or null")
		}
		email, has = e, true
	default:
		errs = append(errs, "an address is text with an @, at most 320 characters, or null")
	}
	if len(errs) > 0 {
		return "", false, errors.New(errorList(errs))
	}
	return email, has, nil
}

// SPDX-License-Identifier: EUPL-1.2

package fleetproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"relikey/agent/internal/kcedge"
)

// Enrolment-key rotation towards the fleet (decision 0026 point 3, #26). The desk rotates an edge's enrolment key
// (KeyClerk rotate_edge): its officer and the edge's new key sign a rotation statement, the security officer completes
// it, and from then on the desk refuses the old key. The fleet does not follow the desk: its trust root is its own
// officer registry. So the edge hands the new key over itself, in a handover signed by both keys and carrying the
// desk's statement for the approver to read, and an officer of the fleet's registry approves it with their passkey.
// Until then the fleet holds the old key. A stolen old key alone cannot move the fleet to another key: the handover
// only becomes pending, and the approver compares the new key's fingerprint with the desk's record before approving.

// RotationContext domain-separates a handover's two signatures from every other use of an enrolment key (fleet reports
// are relikey-fleet-report-v1, clerk requests kc-edge-request-v2).
const RotationContext = "relikey-fleet-rotation-v1"

// MaxStatement bounds the statement a handover carries: one officer, one node, two signatures.
const MaxStatement = 8 << 10

// Statement is the desk's rotation statement as the edge's operator staged it: a multi-signed kc-edge-officer-v2,
// {"bytes": base64 canonical JSON, "signatures": [{key, key_id, signature}]}, exactly as KeyClerk wrote it.
type Statement struct {
	Bytes      string               `json:"bytes"`
	Signatures []StatementSignature `json:"signatures"`
}

// StatementSignature is one signer's entry in the statement.
type StatementSignature struct {
	Key       string `json:"key"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// RotationFacts is what a rotation statement says: the edge, the desk's officer and their key, and the new key. The
// officer's signature verifies against the key the statement names itself, so the facts are consistent, not trusted:
// the fleet cannot know the desk's officers, and shows them for the approver to read.
type RotationFacts struct {
	Edge       string `json:"edge"`
	Officer    string `json:"officer"`
	OfficerKey string `json:"officer_key"`
	NewKey     string `json:"new_key"`
}

// CheckStatement reads a rotation statement and checks that it rotates edge to newKey (hex): a kc-edge-officer-v2 with
// purpose rotation, naming exactly one node, whose enrolment key is newKey, signed by exactly that key and the officer
// key it names, every signature over the same canonical bytes.
func CheckStatement(st Statement, edge, newKey string) (RotationFacts, error) {
	if len(st.Bytes) > MaxStatement || len(st.Signatures) > 4 {
		return RotationFacts{}, errors.New("the rotation statement is larger than one officer and one node sign")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return RotationFacts{}, err
	}
	v, err := kcedge.Parse(raw)
	if err != nil {
		return RotationFacts{}, fmt.Errorf("the rotation statement: %w", err)
	}
	signers := make([]string, 0, len(st.Signatures))
	for _, s := range st.Signatures {
		signers = append(signers, s.Key)
	}
	says, err := kcedge.UnsealMulti(v, signers, kcedge.OfficerFormat)
	if err != nil {
		return RotationFacts{}, fmt.Errorf("the rotation statement does not verify: %w", err)
	}
	f := RotationFacts{NewKey: newKey}
	f.Edge, _ = says["edge"].(string)
	f.Officer, _ = says["officer"].(string)
	f.OfficerKey, _ = says["officer_key"].(string)
	nodes, _ := says["nodes"].([]kcedge.Value)
	var node kcedge.Object
	if len(nodes) == 1 {
		node, _ = nodes[0].(kcedge.Object)
	}
	switch {
	case says["purpose"] != "rotation":
		return RotationFacts{}, fmt.Errorf("the statement's purpose is %v, not rotation: give the statement of the "+
			"desk's rotate_edge, not the enrolment's", says["purpose"])
	case f.Edge != edge:
		return RotationFacts{}, fmt.Errorf("the rotation statement is for edge %q, not %q", f.Edge, edge)
	case node == nil || node["enrolment_key"] != newKey:
		return RotationFacts{}, fmt.Errorf("the rotation statement does not name the new key %s as the edge's one node",
			kcedge.KeyID(newKey))
	case f.OfficerKey == "" || f.Officer == "":
		return RotationFacts{}, errors.New("the rotation statement names no officer and officer key")
	}
	want := []string{f.OfficerKey, newKey}
	slices.Sort(want)
	slices.Sort(signers)
	if !slices.Equal(signers, want) {
		return RotationFacts{}, errors.New("the rotation statement is not signed by exactly its officer and the new key: " +
			"the edge co-signs it with the new key (relikey-agent cosign -key NEW), after the officer")
	}
	return f, nil
}

// Handover is what the edge tells the fleet after the desk took its new key.
type Handover struct {
	Edge      string    `json:"edge"`
	OldKey    string    `json:"old_key"` // hex: the key the fleet holds for this edge
	NewKey    string    `json:"new_key"` // hex: the key the desk holds now
	At        time.Time `json:"at"`      // the edge's trusted time when it signed
	Statement Statement `json:"statement"`
}

// SignedHandover is a handover on the wire: its exact JSON bytes and a signature by each key over context and bytes.
// The old key's signature proves the sender is the edge the fleet knows; the new key's that the edge holds the key it
// hands over.
type SignedHandover struct {
	Handover     string `json:"handover"`      // base64 of the exact handover bytes
	OldSignature string `json:"old_signature"` // hex Ed25519 by the old key over RotationContext + "\n" + bytes
	NewSignature string `json:"new_signature"` // hex Ed25519 by the new key, the same message
}

func handoverMessage(raw []byte) []byte { return append([]byte(RotationContext+"\n"), raw...) }

// SignHandover seals a handover with both keys; it names the keys itself, so they cannot disagree with the signers.
func SignHandover(old, next ed25519.PrivateKey, h Handover) (SignedHandover, error) {
	h.OldKey = hex.EncodeToString(old.Public().(ed25519.PublicKey))
	h.NewKey = hex.EncodeToString(next.Public().(ed25519.PublicKey))
	raw, err := json.Marshal(h, json.Deterministic(true))
	if err != nil {
		return SignedHandover{}, err
	}
	msg := handoverMessage(raw)
	return SignedHandover{Handover: base64.StdEncoding.EncodeToString(raw),
		OldSignature: hex.EncodeToString(ed25519.Sign(old, msg)), NewSignature: hex.EncodeToString(ed25519.Sign(next, msg))}, nil
}

// VerifyHandover checks a handover against the keys the fleet holds now, by edge name: the old key must be the one
// held for that edge, both signatures must verify, the time must lie within Skew of now, and the statement must rotate
// this edge to the new key (CheckStatement). It returns the handover and what its statement says. The reasons are for
// the service's log: an edge is told only that it was refused.
func VerifyHandover(s SignedHandover, held map[string]ed25519.PublicKey, now time.Time) (Handover, RotationFacts, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s.Handover)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s.Handover {
		return Handover{}, RotationFacts{}, errors.New("handover: not canonical base64")
	}
	oldSig, err1 := hex.DecodeString(s.OldSignature)
	newSig, err2 := hex.DecodeString(s.NewSignature)
	if err1 != nil || err2 != nil || len(oldSig) != ed25519.SignatureSize || len(newSig) != ed25519.SignatureSize {
		return Handover{}, RotationFacts{}, errors.New("handover: each signature is 128 hex characters")
	}
	var h Handover
	if err := json.Unmarshal(raw, &h, json.RejectUnknownMembers(true)); err != nil {
		return Handover{}, RotationFacts{}, fmt.Errorf("handover: %w", err)
	}
	key, known := held[h.Edge]
	switch {
	case !known:
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: not a known edge", h.Edge)
	case h.OldKey != hex.EncodeToString(key):
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: its old key %s is not the key the fleet holds "+
			"for it", h.Edge, kcedge.KeyID(h.OldKey))
	case !ed25519.Verify(key, handoverMessage(raw), oldSig):
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: the old key's signature does not verify", h.Edge)
	}
	next, err := kcedge.PublicKey(h.NewKey)
	switch {
	case err != nil:
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: the new key: %w", h.Edge, err)
	case h.NewKey == h.OldKey:
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: the new key is the old one", h.Edge)
	case !ed25519.Verify(next, handoverMessage(raw), newSig):
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: the new key's signature does not verify", h.Edge)
	}
	if d := h.At.Sub(now); d > Skew || d < -Skew {
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: its time is %s from ours", h.Edge, d.Round(time.Second))
	}
	f, err := CheckStatement(h.Statement, h.Edge, h.NewKey)
	if err != nil {
		return Handover{}, RotationFacts{}, fmt.Errorf("handover from %q: %w", h.Edge, err)
	}
	return h, f, nil
}

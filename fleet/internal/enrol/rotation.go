// SPDX-License-Identifier: EUPL-1.2

package enrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"relikey/fleet/internal/registry"
)

// MinTypedKey is how many hex characters of the new key the approver types: 80 bits, as for an activation.
const MinTypedKey = 20

// RotationApproval is what one officer's passkey approves for an edge's enrolment-key rotation (decision 0026 point
// 3, #26): the edge, the key the fleet holds and the new one, the new key's characters as read from a source the edge
// cannot write (the desk's rotation record, or the edge's own screen where the key was made), and who read them. The
// handover proves the edge holds both keys; this proves an officer checked that the new key is the desk's, so a
// stolen old key alone cannot move the fleet.
type RotationApproval struct {
	Fleet    string `json:"fleet"`
	Approver string `json:"approver"` // the officer's id
	Rotation string `json:"rotation"` // the pending rotation's id
	Edge     string `json:"edge"`
	OldKey   string `json:"old_key"`
	NewKey   string `json:"new_key"`
	Typed    string `json:"typed"`    // what the approver typed of the new key
	ReadBy   string `json:"read_by"`  // who read it
	ReadHow  string `json:"read_how"` // "desk record", "on site", "phone", ...
}

// Hash is the approval's identity, the Body of the statement the passkey signs.
func (a RotationApproval) Hash() string {
	b, _ := json.Marshal(a, json.Deterministic(true))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// CheckRotation is ApproveRotation without the signature: a run of at least MinTypedKey hex characters of the new key,
// and who read it and how. The page runs it before asking for the passkey.
func CheckRotation(a RotationApproval) error {
	typed := strings.ToLower(strings.NewReplacer(" ", "", ":", "").Replace(a.Typed))
	switch {
	case len(typed) < MinTypedKey || !strings.Contains(a.NewKey, typed):
		return fmt.Errorf("%s: type at least %d characters of the new key as the desk's rotation record (or the edge "+
			"where it was made) shows it, not from this page", a.Edge, MinTypedKey)
	case a.ReadBy == "" || a.ReadHow == "":
		return fmt.Errorf("%s: record who read the new key and how", a.Edge)
	}
	return nil
}

// ApproveRotation checks an approval against the registry in force and the officer's signature over its statement.
func ApproveRotation(rp registry.RP, reg registry.Registry, a RotationApproval, st registry.Statement, sig registry.Signature,
	now time.Time) error {
	switch {
	case a.Fleet != reg.Fleet || st.Fleet != reg.Fleet:
		return errors.New("a rotation approval for another fleet")
	case st.Kind != "rotate" || st.Body != a.Hash() || st.Registry != reg.Version:
		return errors.New("the statement does not approve this rotation under the registry in force")
	case sig.Officer != a.Approver:
		return errors.New("the signature is not the approver's")
	}
	i := slices.IndexFunc(reg.Officers, func(o registry.Officer) bool { return o.ID == a.Approver })
	if i < 0 {
		return fmt.Errorf("%s is not an officer", a.Approver)
	}
	if _, err := rp.Verify(sig, reg.Officers[i], st, now); err != nil {
		return fmt.Errorf("the approver's passkey: %w", err)
	}
	return CheckRotation(a)
}

// SPDX-License-Identifier: EUPL-1.2

package enrol

import (
	"strings"
	"testing"
	"time"

	"relikey/fleet/internal/registry"
)

// A rotation is approved by one officer of the registry in force, with their passkey over this approval's statement,
// and a run of at least 20 characters of the new key (80 bits) with who read it and how; anything less is refused.
func TestARotationApprovalNeedsTheOfficersPasskeyAndTheNewKeysCharacters(t *testing.T) {
	ann, bob, cat := newPasskey("ann"), newPasskey("bob"), newPasskey("cat")
	reg := registry.Registry{Fleet: "fleet-1", Version: 1, Officers: []registry.Officer{ann.officer(), bob.officer(), cat.officer()}}
	newKey := strings.Repeat("0123456789abcdef", 4)
	a := RotationApproval{Fleet: "fleet-1", Approver: "ann", Rotation: "r1", Edge: "plant-a", OldKey: strings.Repeat("e", 64),
		NewKey: newKey, Typed: newKey[10:30], ReadBy: "ann", ReadHow: "desk record"}
	st := func(a RotationApproval) registry.Statement {
		return registry.Statement{Kind: "rotate", Fleet: "fleet-1", Registry: 1, Body: a.Hash(), Expires: t0.Add(time.Minute), Nonce: "n"}
	}
	if err := ApproveRotation(rp, reg, a, st(a), ann.sign(st(a)), t0); err != nil {
		t.Fatalf("a good approval: %v", err)
	}
	short, wrong, unread := a, a, a
	short.Typed, wrong.Typed, unread.ReadBy = newKey[:19], strings.Repeat("f", 20), ""
	activation := st(a)
	activation.Kind = "activate"
	for name, tc := range map[string]struct {
		a   RotationApproval
		st  registry.Statement
		sig registry.Signature
	}{
		"19 characters":                 {short, st(short), ann.sign(st(short))},
		"characters not of the new key": {wrong, st(wrong), ann.sign(st(wrong))},
		"no one who read it":            {unread, st(unread), ann.sign(st(unread))},
		"another officer's signature":   {a, st(a), bob.sign(st(a))},
		"a stranger's passkey":          {a, st(a), func() registry.Signature { s := newPasskey("dan").sign(st(a)); s.Officer = "ann"; return s }()},
		"an activation statement":       {a, activation, ann.sign(activation)},
		"a statement over another one":  {a, st(short), ann.sign(st(short))},
	} {
		if err := ApproveRotation(rp, reg, tc.a, tc.st, tc.sig, t0); err == nil {
			t.Errorf("%s: approved", name)
		}
	}
}

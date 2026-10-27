// SPDX-License-Identifier: EUPL-1.2

package kcedge_test

import (
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/kcedge"
)

// VerifyEmail on its own (the conformance family arrives with KeyClerk 0.26.0): every check refuses its case.
func TestVerifyEmailRefusesEachWrongAnswer(t *testing.T) {
	bk, other := fakes.Key(1), fakes.Key(7)
	pins := kcedge.Pins{Edge: "edge-a", BundleKey: fakes.Hex(bk)}
	good := func() kcedge.Object {
		return kcedge.Object{"edge": "edge-a", "lease_id": "L-1", "person": "kc:0123456789abcdef0123456789abcdef",
			"email": "ann@example.test", "nonce": "n-1", "issued": time.Now().UTC().Format("2006-01-02T15:04:05Z")}
	}
	if email, has, err := kcedge.VerifyEmail(fakes.Seal(bk, good(), kcedge.EmailFormat), pins, "L-1", "n-1"); err != nil || !has || email != "ann@example.test" {
		t.Fatalf("a good answer refused: %q %v %v", email, has, err)
	}
	none := good()
	none["email"] = nil
	if _, has, err := kcedge.VerifyEmail(fakes.Seal(bk, none, kcedge.EmailFormat), pins, "L-1", "n-1"); err != nil || has {
		t.Fatalf("email null: has %v, err %v", has, err)
	}
	for name, c := range map[string]struct {
		change       func(kcedge.Object)
		key          string
		format       string
		lease, nonce string
	}{
		"another edge":    {change: func(o kcedge.Object) { o["edge"] = "edge-b" }},
		"another lease":   {lease: "L-2"},
		"another request": {nonce: "n-2"},
		"no person":       {change: func(o kcedge.Object) { delete(o, "person") }},
		"no @":            {change: func(o kcedge.Object) { o["email"] = "ann.example.test" }},
		"too long":        {change: func(o kcedge.Object) { o["email"] = strings.Repeat("a", 320) + "@x" }},
		"not text":        {change: func(o kcedge.Object) { o["email"] = kcedge.Number("5") }},
		"no issued":       {change: func(o kcedge.Object) { delete(o, "issued") }},
		"another key":     {key: "other"},
		"another format":  {format: kcedge.EndedFormat},
	} {
		o := good()
		if c.change != nil {
			c.change(o)
		}
		k, f, lease, nonce := bk, kcedge.EmailFormat, "L-1", "n-1"
		if c.key != "" {
			k = other
		}
		if c.format != "" {
			f = c.format
		}
		if c.lease != "" {
			lease = c.lease
		}
		if c.nonce != "" {
			nonce = c.nonce
		}
		if _, _, err := kcedge.VerifyEmail(fakes.Seal(k, o, f), pins, lease, nonce); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

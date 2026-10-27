// SPDX-License-Identifier: EUPL-1.2

package testemit_test

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/testemit"
)

// The second emitter against the agent's verifier (decision 0017 point 6): what it emits by the profile is accepted,
// and each way of breaking the profile is refused, or leaves the decision not live, as the profile says.

var (
	now    = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	grant  = testemit.Grant{ID: "G-1", Person: "broker:ann", Username: "ann", Email: "ann@example.test", Target: "plc-ssh", Role: "plc-operators", Class: "low", From: now.Add(-time.Hour), Until: now.Add(48 * time.Hour)}
	others = testemit.Grant{ID: "G-2", Person: "broker:eve", Username: "eve", Email: "eve@example.test", Target: "plc-ssh", Role: "plc-operators", Class: "low", From: now.Add(-time.Hour), Until: now.Add(48 * time.Hour)}
)

func emitter() *testemit.Emitter {
	return &testemit.Emitter{Edge: "edge-x", BundleKey: testemit.Key("bundle"), OfficerKey: testemit.Key("officer"),
		Serial: 10, CeilingSerial: 3, Horizons: map[string]int64{"low": 168, "elevated": 24, "privileged": 1},
		Persons: []string{"broker:ann"}, Targets: []string{"plc-ssh"}, MaxLease: 720, MaxOffline: 72}
}

func pins(e *testemit.Emitter) kcedge.Pins {
	edge, bk, ok := e.Pins()
	return kcedge.Pins{Edge: edge, BundleKey: bk, OfficerKey: ok}
}

// verify passes the emitted object through JSON, as the wire does, and through the agent's verifier.
func verify(t *testing.T, sealed map[string]any, p kcedge.Pins, st kcedge.State, at time.Time) (*kcedge.Applied, error) {
	t.Helper()
	b, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	v, err := kcedge.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := kcedge.SealedFrom(v)
	if err != nil {
		return nil, err
	}
	return kcedge.VerifyBundle(s, p, st, at, kcedge.CeilingPolicyGo)
}

func live(a *kcedge.Applied) []string {
	ids := []string{}
	for _, l := range a.Leases {
		ids = append(ids, l.LeaseID)
	}
	return ids
}

func TestTheSecondEmittersBundleIsAccepted(t *testing.T) {
	e := emitter()
	a, err := verify(t, e.Bundle(now, []testemit.Grant{grant}, nil), pins(e), kcedge.State{Serial: 9}, now)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if got := live(a); !slices.Equal(got, []string{"G-1"}) {
		t.Fatalf("live %v", got)
	}
	if a.GovernedRoles != nil {
		t.Fatalf("no catalogue was sent, got %v", *a.GovernedRoles)
	}
	if a.State.Serial != 10 || a.State.CeilingSerial != 3 {
		t.Fatalf("floors %+v", a.State)
	}
	e.Governed = []string{"plc-operators"}
	e.Serial++
	if a, err = verify(t, e.Bundle(now, []testemit.Grant{grant}, nil), pins(e), a.State, now); err != nil ||
		a.GovernedRoles == nil || !slices.Equal(*a.GovernedRoles, []string{"plc-operators"}) {
		t.Fatalf("governed roles: %v %v", a, err)
	}
	e.Governed, e.Serial = []string{}, e.Serial+1
	if a, err = verify(t, e.Bundle(now, nil, nil), pins(e), a.State, now); err != nil || a.GovernedRoles == nil || len(*a.GovernedRoles) != 0 {
		t.Fatalf("signed and empty must read as none governed: %v %v", a, err)
	}
}

// Each case breaks one property of the profile (model/edge-decision-interface.yaml, verifications_the_agent_runs).
func TestEachBreachOfTheProfileIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		build func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time)
	}{
		{"a bundle signed with a key the edge did not pin", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			p := pins(e)
			e.BundleKey = testemit.Key("intruder")
			return e.Bundle(now, []testemit.Grant{grant}, nil), p, kcedge.State{}, now
		}},
		{"one key for bundle and ceiling (the officer's independence lost)", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			p := pins(e)
			e.OfficerKey = e.BundleKey
			return e.Bundle(now, []testemit.Grant{grant}, nil), p, kcedge.State{}, now
		}},
		{"signed bytes re-serialised on the way", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return testemit.Reserialised(e.Bundle(now, []testemit.Grant{grant}, nil)), pins(e), kcedge.State{}, now
		}},
		{"a bundle for another edge", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			p := pins(e)
			p.Edge = "edge-y"
			return e.Bundle(now, []testemit.Grant{grant}, nil), p, kcedge.State{}, now
		}},
		{"a serial not above the floor (replay)", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return e.Bundle(now, []testemit.Grant{grant}, nil), pins(e), kcedge.State{Serial: e.Serial}, now
		}},
		{"issued in the future beyond the skew", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return e.Bundle(now.Add(10*time.Minute), []testemit.Grant{grant}, nil), pins(e), kcedge.State{}, now
		}},
		{"issued before the newest signed time seen", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return e.Bundle(now.Add(-2*time.Hour), []testemit.Grant{grant}, nil), pins(e), kcedge.State{Newest: "2026-10-25T11:00:00Z"}, now
		}},
		{"the edge's clock before the newest signed time seen", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return e.Bundle(now, []testemit.Grant{grant}, nil), pins(e), kcedge.State{Newest: "2026-10-25T12:30:00Z"}, now.Add(-time.Hour)
		}},
		{"a ceiling older than the one held", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return e.Bundle(now, []testemit.Grant{grant}, nil), pins(e), kcedge.State{CeilingSerial: e.CeilingSerial + 1}, now
		}},
		{"a malformed governed-roles member", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			e.Governed = []string{"plc-operators", "plc-operators"}
			return e.Bundle(now, []testemit.Grant{grant}, nil), pins(e), kcedge.State{}, now
		}},
		{"leases without a ceiling", func(e *testemit.Emitter) (map[string]any, kcedge.Pins, kcedge.State, time.Time) {
			return withoutCeiling(e), pins(e), kcedge.State{}, now
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sealed, p, st, at := c.build(emitter())
			a, err := verify(t, sealed, p, st, at)
			if err == nil {
				t.Fatalf("accepted, live %v", live(a))
			}
			if !strings.Contains(err.Error(), because[c.name]) {
				t.Fatalf("refused for another reason: %v (want %q)", err, because[c.name])
			}
		})
	}
}

// because is the reason each breach must be refused for, so a case cannot pass on an unrelated refusal.
var because = map[string]string{
	"a bundle signed with a key the edge did not pin":                  "not the pinned key",
	"one key for bundle and ceiling (the officer's independence lost)": "not signed with the edge officer's key",
	"signed bytes re-serialised on the way":                            "does not verify over the bytes",
	"a bundle for another edge":                                        "a bundle for another edge",
	"a serial not above the floor (replay)":                            "not above the floor",
	"issued in the future beyond the skew":                             "issued in the future",
	"issued before the newest signed time seen":                        "issued before the newest signed time seen",
	"the edge's clock before the newest signed time seen":              "the clock is before the newest signed time seen",
	"a ceiling older than the one held":                                "a ceiling older than the one held",
	"a malformed governed-roles member":                                "governed_roles: each role once",
	"leases without a ceiling":                                         "leases without a ceiling",
}

func TestADecisionOutsideTheCeilingOrItsHorizonIsNotLive(t *testing.T) {
	e := emitter()
	a, err := verify(t, e.Bundle(now, []testemit.Grant{grant, others}, nil), pins(e), kcedge.State{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(live(a), []string{"G-1"}) || !slices.Contains(a.RefusedByCeiling, "G-2") {
		t.Fatalf("a person outside the ceiling was admitted: live %v, refused %v", live(a), a.RefusedByCeiling)
	}
	// Offline past the class horizon (low: 168 h, capped by the ceiling's 72 h offline): the lease ends on the edge.
	issued := now.Add(-100 * time.Hour)
	g := grant
	g.From, g.Until = issued.Add(-time.Hour), now.Add(48*time.Hour)
	a, err = verify(t, e.Bundle(issued, []testemit.Grant{g}, nil), pins(e), kcedge.State{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(live(a)) != 0 {
		t.Fatalf("a lease outlived its offline horizon: %v", live(a))
	}
}

// withoutCeiling emits a bundle whose ceiling member is null: the bundle key signs, the officer did not.
func withoutCeiling(e *testemit.Emitter) map[string]any {
	sealed := e.Bundle(now, []testemit.Grant{grant}, nil)
	raw := decode(sealed)
	raw["ceiling"] = nil
	delete(raw, "format")
	delete(raw, "key_id")
	return testemit.Seal(e.BundleKey, raw, "kc-edge-bundle-v3")
}

func decode(sealed map[string]any) map[string]any {
	var b []byte
	b, _ = json.Marshal(sealed["bytes"])
	var s string
	_ = json.Unmarshal(b, &s)
	raw, _ := base64Decode(s)
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	_ = d.Decode(&m)
	return m
}

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

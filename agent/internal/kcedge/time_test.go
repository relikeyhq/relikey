// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"encoding/json/jsontext"
	"slices"
	"testing"
	"time"
)

// KeyClerk's time family (edge protocol 1.5, section 1): verify_time's verdicts for the desk's time.
func TestReferenceTimeVerdicts(t *testing.T) {
	var set struct {
		Time struct {
			Cases []struct {
				Name     string         `json:"name"`
				Sealed   jsontext.Value `json:"sealed"`
				Pins     Pins           `json:"pins"`
				Nonce    string         `json:"nonce"`
				Waited   float64        `json:"waited"`
				Expected struct {
					OK     bool    `json:"ok"`
					Issued *string `json:"issued"`
				} `json:"expected"`
			} `json:"cases"`
		} `json:"time"`
	}
	load(t, "edge.json", &set)
	if len(set.Time.Cases) == 0 {
		t.Fatal("no time cases")
	}
	for _, c := range set.Time.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var issued time.Time
			sv, err := Parse(c.Sealed)
			if err == nil {
				var s Sealed
				if s, err = SealedFrom(sv); err == nil {
					issued, err = VerifyTime(s, c.Pins, c.Nonce, time.Duration(c.Waited*float64(time.Second)))
				}
			}
			if (err == nil) != c.Expected.OK {
				t.Fatalf("ok = %v, want %v (%v)", err == nil, c.Expected.OK, err)
			}
			if c.Expected.OK && issued.Format("2006-01-02T15:04:05Z") != *c.Expected.Issued {
				t.Fatalf("issued %s, want %s", issued, *c.Expected.Issued)
			}
		})
	}
}

// KeyClerk's admit cases that carry now_start (edge protocol 1.5): a lease's or visit lease's start is judged on the
// earlier reading, its end on the trusted time. Times in the cases are seconds; person, target and revocation as given.
func TestAdmitStartsOnTheEarlierReading(t *testing.T) {
	type window struct {
		LeaseID string   `json:"lease_id"`
		Person  string   `json:"person"`
		Target  string   `json:"target"`
		Targets []string `json:"targets"`
		From    int64    `json:"from"`
		Until   int64    `json:"until"`
	}
	var set struct {
		Cases []struct {
			Name       string `json:"name"`
			Entrypoint string `json:"entrypoint"`
			Input      struct {
				Now         int64    `json:"now"`
				NowStart    *int64   `json:"now_start"`
				Person      string   `json:"person"`
				Target      string   `json:"target"`
				Revoked     []string `json:"revoked"`
				Leases      []window `json:"leases"`
				VisitLeases []window `json:"visit_leases"`
			} `json:"input"`
			Expected struct {
				Allow  bool     `json:"allow"`
				Leases []string `json:"leases"`
			} `json:"expected"`
		} `json:"cases"`
	}
	load(t, "edge.json", &set)
	sec := func(s int64) time.Time { return time.Unix(s, 0).UTC() }
	n := 0
	for _, c := range set.Cases {
		if c.Entrypoint != "keyclerk/edge/admit" || c.Input.NowStart == nil {
			continue
		}
		n++
		in := c.Input
		now, start := sec(in.Now), sec(*in.NowStart)
		got := []string{}
		for _, l := range in.Leases {
			if l.Person == in.Person && l.Target == in.Target && !slices.Contains(in.Revoked, l.LeaseID) &&
				leaseLive(sec(l.From), sec(l.Until), now, start) {
				got = append(got, l.LeaseID)
			}
		}
		visit := false
		for _, v := range in.VisitLeases {
			if v.Person == in.Person && slices.Contains(v.Targets, in.Target) && !slices.Contains(in.Revoked, v.LeaseID) &&
				leaseLive(sec(v.From), sec(v.Until), now, start) {
				visit = true
			}
		}
		if allow := len(got) > 0 || visit; allow != c.Expected.Allow || !equalStrings(got, c.Expected.Leases) {
			t.Errorf("%s: allow %v %v, want %v %v", c.Name, allow, got, c.Expected.Allow, c.Expected.Leases)
		}
	}
	if n < 3 {
		t.Fatalf("only %d admit cases with now_start", n)
	}
}

// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"encoding/json"
	"testing"
	"time"
)

// The site key's statements (edge protocol 1.6 section 14) as KeyClerk's verify_site judges them
// (testdata/gen_site.py): the agent agrees on every verdict, at each case's now, and on what an accepted one says.
func TestSiteStatementsAsTheReferenceJudgesThem(t *testing.T) {
	var set struct {
		Edge    string `json:"edge"`
		SiteKey string `json:"site_key"`
		Cases   []struct {
			Name      string          `json:"name"`
			Purpose   string          `json:"purpose"`
			Now       string          `json:"now"`
			Statement json.RawMessage `json:"statement"`
			Expected  struct {
				OK      bool   `json:"ok"`
				NodeKey string `json:"node_key"`
				At      string `json:"at"`
				Reason  string `json:"reason"`
			} `json:"expected"`
		} `json:"cases"`
	}
	load(t, "site.json", &set)
	if len(set.Cases) < 18 {
		t.Fatalf("only %d site cases", len(set.Cases))
	}
	for _, c := range set.Cases {
		now, err := ParseTime(c.Now)
		if err != nil {
			t.Fatalf("%s: now: %v", c.Name, err)
		}
		v, err := Parse(c.Statement)
		var st Object
		if err == nil {
			st, err = VerifySite(v, set.SiteKey, set.Edge, c.Purpose, now)
		}
		if (err == nil) != c.Expected.OK {
			t.Errorf("%s: ok = %v, want %v (%v)", c.Name, err == nil, c.Expected.OK, err)
			continue
		}
		if c.Expected.OK && (st["node_key"] != c.Expected.NodeKey || st["at"] != c.Expected.At || st["reason"] != c.Expected.Reason) {
			t.Errorf("%s: says %v, want node %s at %s", c.Name, st, c.Expected.NodeKey, c.Expected.At)
		}
	}
}

// KeyClerk's own conformance family for site statements (testdata/site_kc.json, from its edge.json): the same verdicts.
func TestKeyClerksSiteFamily(t *testing.T) {
	var set struct {
		Cases []struct {
			Name     string          `json:"name"`
			Edge     string          `json:"edge"`
			SiteKey  string          `json:"site_key"`
			Purpose  string          `json:"purpose"`
			Now      string          `json:"now"`
			Sealed   json.RawMessage `json:"sealed"`
			Expected struct {
				OK bool `json:"ok"`
			} `json:"expected"`
		} `json:"cases"`
	}
	load(t, "site_kc.json", &set)
	if len(set.Cases) < 7 {
		t.Fatalf("only %d cases in KeyClerk's site family", len(set.Cases))
	}
	for _, c := range set.Cases {
		now, err := ParseTime(c.Now)
		if err != nil {
			t.Fatalf("%s: now: %v", c.Name, err)
		}
		v, err := Parse(c.Sealed)
		if err == nil {
			_, err = VerifySite(v, c.SiteKey, c.Edge, c.Purpose, now)
		}
		if (err == nil) != c.Expected.OK {
			t.Errorf("%s: ok = %v, want %v (%v)", c.Name, err == nil, c.Expected.OK, err)
		}
	}
}

func TestASiteStatementNeedsAKnownPurpose(t *testing.T) {
	if _, err := VerifySite(Object{}, "00", "plant-a", "rotation", time.Time{}); err == nil {
		t.Fatal("a purpose outside provisional and promotion is refused before anything is read")
	}
}

// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"encoding/json"
	"testing"
)

// The site key's statements (edge protocol 1.5 section 14) as KeyClerk's verify_site judges them
// (testdata/gen_site.py, from the pinned tag): the agent agrees on every verdict and on what an accepted one says.
func TestSiteStatementsAsTheReferenceJudgesThem(t *testing.T) {
	var set struct {
		Edge    string `json:"edge"`
		SiteKey string `json:"site_key"`
		Cases   []struct {
			Name      string          `json:"name"`
			Purpose   string          `json:"purpose"`
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
	if len(set.Cases) < 10 {
		t.Fatalf("only %d site cases", len(set.Cases))
	}
	for _, c := range set.Cases {
		v, err := Parse(c.Statement)
		var st Object
		if err == nil {
			st, err = VerifySite(v, set.SiteKey, set.Edge, c.Purpose)
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

func TestASiteStatementNeedsAKnownPurpose(t *testing.T) {
	if _, err := VerifySite(Object{}, "00", "plant-a", "rotation"); err == nil {
		t.Fatal("a purpose outside provisional and promotion is refused before anything is read")
	}
}

// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"relikey/agent/internal/agent"
)

// The site-statement vectors (internal/kcedge/testdata/site.json, from KeyClerk's verify_site): seed keys 21 (site),
// 22 (the node it names) and 23 (another node).
type siteVectors struct {
	SiteKey string `json:"site_key"`
	Cases   []struct {
		Name      string         `json:"name"`
		Statement jsontext.Value `json:"statement"`
	} `json:"cases"`
}

func siteSet(t *testing.T) siteVectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "kcedge", "testdata", "site.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v siteVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v siteVectors) statement(t *testing.T, name string) []byte {
	t.Helper()
	for _, c := range v.Cases {
		if c.Name == name {
			return c.Statement
		}
	}
	t.Fatalf("no site case %q", name)
	return nil
}

// promoteRig is a node's configuration with the site key pinned, its enrolment key (seed n) and a statement file.
func promoteRig(t *testing.T, seed byte, siteKey string, stmt []byte) (cfg, stateDir, stmtFile string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "enrolment.key")
	seedBytes := make([]byte, 32)
	for i := range seedBytes {
		seedBytes[i] = seed
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(seedBytes)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pins := `"pins": {"bundle_key": "` + key + `", "officer_key": "` + key + `"` +
		map[bool]string{true: `, "site_key": "` + siteKey + `"`, false: ""}[siteKey != ""] + `}`
	body := `{"edge": "plant-a", "mode": "shadow", "state_dir": "` + filepath.ToSlash(stateDir) + `", "enrolment_key_file": "` +
		filepath.ToSlash(keyFile) + `", ` + pins + `, ` + clerkOK + `, ` + bastionOK + `}`
	cfg = filepath.Join(dir, "agent.json")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stmtFile = filepath.Join(dir, "promotion.json")
	if err := os.WriteFile(stmtFile, stmt, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, stateDir, stmtFile
}

// decision 0028: the spare's promotion is checked against the pinned site key and this node, recorded whole, and
// reported as a break_glass activation; the same statement never promotes twice.
func TestPromoteRecordsABreakGlassActivationForThisNode(t *testing.T) {
	v := siteSet(t)
	good := v.statement(t, "a promotion signed by the site key and the node it names")
	cfg, stateDir, stmt := promoteRig(t, 22, v.SiteKey, good)
	if err := promote([]string{"-config", cfg, "-statement", stmt}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	act, err := agent.ReadActivation(filepath.Join(stateDir, agent.ActivationName))
	if err != nil || act == nil || act.By != "break_glass" || len(act.Statement) == 0 {
		t.Fatalf("activation %+v, %v", act, err)
	}
	want := jsontext.Value(good)
	_ = want.Compact()
	if string(act.Statement) != string(want) {
		t.Fatal("the statement is not recorded whole, as given")
	}
	if err := promote([]string{"-config", cfg, "-statement", stmt}); err == nil || !strings.Contains(err.Error(), "newer statement") {
		t.Fatalf("the same statement promoted again: %v", err)
	}
}

func TestPromoteRefusesWithTheNextStep(t *testing.T) {
	v := siteSet(t)
	good := v.statement(t, "a promotion signed by the site key and the node it names")
	for _, tc := range []struct {
		name      string
		seed      byte
		site      string
		stmt      []byte
		why, next string
	}{
		{"no site key pinned", 22, "", good, "pins.site_key is not set", "as the officer recorded it at the desk"},
		{"another node's statement", 23, v.SiteKey, good, "not this node", "Run promote on the node it names"},
		{"a provisional statement", 22, v.SiteKey, v.statement(t, "a provisional statement"), "is not one for promotion",
			"Ask the officer for a promotion statement"},
		{"signed by the site key alone", 22, v.SiteKey, v.statement(t, "signed by the site key alone"), "signed by exactly",
			"nothing was recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, stateDir, stmt := promoteRig(t, tc.seed, tc.site, tc.stmt)
			err := promote([]string{"-config", cfg, "-statement", stmt})
			if err == nil || !strings.Contains(err.Error(), tc.why) || !strings.Contains(err.Error(), tc.next) {
				t.Fatalf("got %v, want %q and %q", err, tc.why, tc.next)
			}
			if _, err := os.Stat(filepath.Join(stateDir, agent.ActivationName)); err == nil {
				t.Fatal("a refused promotion recorded an activation")
			}
		})
	}
}

func TestASiteKeyEqualToTheOfficersIsRefused(t *testing.T) {
	_, err := loadConfig(write(t, strings.Replace(config(clerkOK, bastionOK), `"officer_key": "`+key+`"`,
		`"officer_key": "`+key+`", "site_key": "`+key+`"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "a key of its own") {
		t.Fatalf("got %v", err)
	}
}

// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"relikey/agent/internal/agent"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/keyclerk"
)

// promote makes this node the edge's active node by hand (decision 0028, a spare taking over): it checks the site
// key's promotion statement (edge protocol 1.5 section 14) for this edge and this node, against pins.site_key, and
// records the activation in the state directory; the agent reports it as a break_glass activation (section 7.3) from
// its next report, and the desk records the promotion and raises its incident.
func promote(args []string) error {
	fs := flag.NewFlagSet("promote", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/relikey/agent.json", "the agent's configuration")
	stmtPath := fs.String("statement", "", "the site key's promotion statement for this node (kc-edge-site-v1)")
	_ = fs.Parse(args)
	if *stmtPath == "" {
		return errors.New("usage: relikey-agent promote [-config FILE] -statement STATEMENT")
	}
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if c.Pins.SiteKey == "" {
		return errors.New("pins.site_key is not set: a promotion is checked against the site's physical key. Add it to " +
			"agent.json as the officer recorded it at the desk (the edge's site_key), then run promote again")
	}
	key, err := enrolmentKey(c.EnrolmentKeyFile)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*stmtPath)
	if err != nil {
		return err
	}
	v, err := kcedge.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: not JSON (%w); give the statement edge_cli site-statement wrote, signed by the site key "+
			"and this node", *stmtPath, err)
	}
	st, err := kcedge.VerifySite(v, c.Pins.SiteKey, c.Edge, "promotion")
	if err != nil {
		return fmt.Errorf("%s: %w; nothing was recorded. Ask the officer for a promotion statement for edge %s and "+
			"this node, signed by the site key and this node (relikey-agent cosign signs officer statements; the "+
			"site statement is signed with KeyClerk's edge_cli cosign under kc-edge-site-v1)", *stmtPath, err, c.Edge)
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if st["node_key"] != pub {
		return fmt.Errorf("the statement promotes node %v, not this node (%s): nothing was recorded. Run promote on the "+
			"node it names, or ask for a statement that names this one", st["node_key"], pub)
	}
	path := filepath.Join(c.StateDir, agent.ActivationName)
	if old, err := agent.ReadActivation(path); err == nil && old != nil && old.By == "break_glass" {
		if ov, err := kcedge.Parse(old.Statement); err == nil {
			if ost, err := kcedge.VerifySite(ov, c.Pins.SiteKey, c.Edge, "promotion"); err == nil {
				if oa, _ := ost["at"].(string); oa >= st["at"].(string) {
					return fmt.Errorf("this node was promoted by a statement of %s already; a promotion needs a newer "+
						"statement than the last one (an old one never promotes again): ask for a fresh one", oa)
				}
			}
		}
	}
	compact := jsontext.Value(raw)
	if err := compact.Compact(); err != nil {
		return err
	}
	act := keyclerk.Activation{By: "break_glass", At: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Statement: compact}
	if err := agent.WriteActivation(path, act); err != nil {
		return fmt.Errorf("%s: %w; the promotion is not recorded", path, err)
	}
	fmt.Printf("promoted: node %s of edge %s by the site key's statement of %s (%s).\n", pub[:16], c.Edge, st["at"], st["reason"])
	if c.Mode != agent.Enforce {
		fmt.Println("next: this agent runs in shadow mode; set \"mode\": \"enforce\" in agent.json and restart it, " +
			"or it applies nothing.")
	}
	fmt.Println("the agent reports this activation (break_glass) from its next report; the desk records it and raises " +
		"its incident.")
	return nil
}

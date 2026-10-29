// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func config(clerk, bastion string) string {
	return `{"edge": "plant-a", "state_dir": "/var/lib/relikey", "enrolment_key_file": "/etc/relikey/enrol.key",
	 "pins": {"bundle_key": "` + key + `", "officer_key": "` + key + `"}, ` + clerk + `, ` + bastion + `}`
}

const clerkOK = `"clerk": {"url": "https://desk.example"}`
const bastionOK = `"bastion": {"kind": "warpgate", "url": "https://127.0.0.1:8888/@warpgate/admin/api",
	"token_file": "/etc/relikey/warpgate.token", "pin_sha256": "` + key + `", "sso_provider": "keycloak"}`

func TestAConfigByRoleLoads(t *testing.T) {
	c, err := loadConfig(write(t, config(clerkOK, bastionOK)))
	if err != nil {
		t.Fatalf("a configuration by role was refused: %v", err)
	}
	if c.Bastion.Kind != "warpgate" || c.Clerk.URL != "https://desk.example" {
		t.Fatalf("read %+v", c)
	}
}

func TestOldProductSectionsAreRefusedWithTheRename(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{config(`"keyclerk": {"url": "https://desk.example"}`, bastionOK), `"keyclerk" section is now "clerk"`},
		{config(clerkOK, strings.Replace(bastionOK, `"bastion": {"kind": "warpgate", `, `"warpgate": {`, 1)),
			`"warpgate" section is now "bastion" with "kind": "warpgate"`},
	} {
		if _, err := loadConfig(write(t, tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("got %v, want an error saying %q", err, tc.want)
		}
	}
}

func TestAnUnknownBastionKindIsRefused(t *testing.T) {
	body := config(clerkOK, strings.Replace(bastionOK, `"kind": "warpgate"`, `"kind": "teleport"`, 1))
	if _, err := loadConfig(write(t, body)); err == nil || !strings.Contains(err.Error(), "has the warpgate adapter only") {
		t.Fatalf("an unknown bastion kind was accepted or refused without why: %v", err)
	}
}

func TestAMissingBastionKindIsNamed(t *testing.T) {
	body := config(clerkOK, strings.Replace(bastionOK, `"kind": "warpgate", `, ``, 1))
	if _, err := loadConfig(write(t, body)); err == nil || !strings.Contains(err.Error(), "bastion.kind") {
		t.Fatalf("a missing kind was not named: %v", err)
	}
}

// A refused configuration says what is wrong and what completes it (issue 22).
func TestARefusedConfigurationSaysWhatToDoNext(t *testing.T) {
	for _, tc := range []struct{ body, why, next string }{
		{config(clerkOK, strings.Replace(bastionOK, `"sso_provider": "keycloak"`, `"sso_provider": ""`, 1)),
			"missing bastion.sso_provider", "deploy/edge/install.py writes a complete configuration"},
		{strings.Replace(config(clerkOK, bastionOK), `"officer_key": "`+key, `"officer_key": "`+strings.ToUpper(key), 1),
			"pins.officer_key: an Ed25519 public key is 64 lower-case hex characters", "as the edge officer gave it"},
	} {
		_, err := loadConfig(write(t, tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.why) || !strings.Contains(err.Error(), tc.next) {
			t.Errorf("got %v, want %q and %q", err, tc.why, tc.next)
		}
	}
}

func TestABadEnrolmentKeySaysHowToRecover(t *testing.T) {
	p := filepath.Join(t.TempDir(), "enrolment.key")
	if err := os.WriteFile(p, []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := enrolmentKey(p); err == nil || !strings.Contains(err.Error(), "restore the enrolment key") {
		t.Fatalf("a bad enrolment key was accepted or refused without the next step: %v", err)
	}
}

// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Enrolment by code (an admin section) with the page: the page's codes need the enrolment address and the CA they
// pin, so a fleet.json without either is refused at load, saying what to set; with both it loads.
func TestEnrolmentNeedsTheCodesAddressAndCA(t *testing.T) {
	const base = `{"listen": "127.0.0.1:8093", "state": "inv.json", "admin": {"state": "admin.json", "fleet": "fleet-1"},
	"page": {"listen": "127.0.0.1:8094", "issuer": "https://id.example/realms/r", "client_id": "fleet",
	"secret_file": "s", "redirect_url": "https://fleet.example/callback", "ca_file": "ca.pem"%s}}`
	for name, c := range map[string]struct {
		extra string
		ok    bool
	}{
		"both":               {`, "enrol_url": "https://edge.example/fleet/v1/enrol", "pin_ca_file": "fleet-ca.pem"`, true},
		"no enrol_url":       {`, "pin_ca_file": "fleet-ca.pem"`, false},
		"an http enrol_url":  {`, "enrol_url": "http://edge.example/fleet/v1/enrol", "pin_ca_file": "fleet-ca.pem"`, false},
		"no pin_ca_file":     {`, "enrol_url": "https://edge.example/fleet/v1/enrol"`, false},
		"neither of the two": {``, false},
	} {
		path := filepath.Join(t.TempDir(), "fleet.json")
		if err := os.WriteFile(path, []byte(strings.Replace(base, "%s", c.extra, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := load(path)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want loaded %v", name, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "page.enrol_url") {
			t.Errorf("%s: the refusal does not say what to set: %v", name, err)
		}
	}
}

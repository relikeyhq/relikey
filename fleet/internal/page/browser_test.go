// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"relikey/fleet/internal/admin"
)

// The anchor ceremony in a real browser (Chromium through Playwright, a virtual authenticator over CDP): the page's
// script as shipped, under the page's policy, against the page's routes. Needs Python with Playwright and Chromium,
// so it runs when RELIKEY_BROWSER is set (RELIKEY_PYTHON names the interpreter); build.py check sets it when they
// are there.
func TestTheAnchorCeremonyInABrowser(t *testing.T) {
	if os.Getenv("RELIKEY_BROWSER") == "" {
		t.Skip("set RELIKEY_BROWSER=1 to run it (Python Playwright and Chromium)")
	}
	b, p, srv, _ := rig(t)
	st, _ := admin.Open(filepath.Join(t.TempDir(), "admin.json"), "fleet-1")
	p.Admin = st
	p.Cfg.Officers = []string{"ann", "bob", "cat"}
	// WebAuthn takes no IP address as the relying party: the browser opens the page as localhost
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	p.Cfg.RedirectURL, p.OAuth.RedirectURL = u+"/callback", u+"/callback"
	py := os.Getenv("RELIKEY_PYTHON")
	if py == "" {
		py = "python"
	}
	out, err := exec.CommandContext(t.Context(), py, "-P", filepath.Join("testdata", "browser_ceremony.py"), u, b.URL).CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("the browser walk failed: %v", err)
	}
	if st.Anchor() == "" {
		t.Fatal("the browser walk ended without an anchor")
	}
}

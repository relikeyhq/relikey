// SPDX-License-Identifier: EUPL-1.2

package page

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/registry/regtest"
)

var rpFuzz = (&Page{Cfg: Config{RedirectURL: "https://localhost/callback"}}).rp()

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// FuzzCeremonyRoutes throws arbitrary bodies at the passkey routes of a signed-in named officer: whatever comes, no
// panic, a JSON answer, and no passkey recorded or anchor set unless a real ceremony did it.
func FuzzCeremonyRoutes(f *testing.F) {
	key := regtest.New("es256", false)
	cd, att := key.Create(rpFuzz, make([]byte, 32), regtest.Tweak{})
	e := base64.RawURLEncoding.EncodeToString
	good, _ := json.Marshal(map[string]string{"client_data_json": e(cd), "attestation_object": e(att)})
	f.Add(uint8(1), good)
	f.Add(uint8(3), []byte(`{"client_data_json":"","authenticator_data":"","signature":""}`))
	f.Add(uint8(0), []byte(`{}`))
	f.Add(uint8(2), []byte(`[`))
	paths := []string{"/officer/begin", "/officer/finish", "/anchor/begin", "/anchor/sign"}
	st, _ := admin.Open(filepath.Join(f.TempDir(), "admin.json"), "fleet-1")
	p := &Page{Cfg: Config{RedirectURL: "https://localhost/callback", Officers: []string{"ann", "bob", "cat"}},
		Admin: st, Now: time.Now, Log: discard()}
	p.sessions = map[string]session{"s1": {sub: "sub-ann", name: "ann", until: time.Now().Add(time.Hour)}}
	h := p.Handler()
	f.Fuzz(func(t *testing.T, route uint8, body []byte) {
		req := httptest.NewRequest("POST", "https://localhost"+paths[int(route)%len(paths)], strings.NewReader(string(body)))
		req.Host = "localhost"
		req.Header.Set("Origin", "https://localhost")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "s1"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%d not JSON: %q", w.Code, w.Body.String())
		}
		if len(st.Candidates()) != 0 || st.Anchor() != "" {
			t.Fatal("a fuzzed body registered a passkey or set an anchor") // the challenge is random: no body can answer it
		}
	})
}

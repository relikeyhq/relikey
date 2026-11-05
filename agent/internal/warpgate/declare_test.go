// SPDX-License-Identifier: EUPL-1.2

package warpgate_test

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/warpgate"
)

// The declaration follows the version Warpgate reports to the admin token: ends_sessions_on_revoke from 0.30.2
// (warp-tech/warpgate#2789), never on a version it cannot read.
func TestTheDeclarationFollowsTheVersion(t *testing.T) {
	for _, c := range []struct {
		shown string
		ends  bool
	}{{"v0.30.1", false}, {"v0.30.2", true}, {"v0.30.4", true}, {"v0.31.0-rc.1", true}, {"v1.0.0", true},
		{"v0.29.9", false}, {"nightly", false}} {
		w := fakes.NewWarpgate("tok", nil)
		w.Version = c.shown
		srv := httptest.NewTLSServer(w.Handler())
		b := warpgate.Bastion{C: &warpgate.Client{Base: srv.URL + "/@warpgate/admin/api", Token: "tok", HTTP: srv.Client()}}
		d, err := b.Declare(context.Background())
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", c.shown, err)
		}
		if d.Product != "warpgate" || d.Version != strings.TrimPrefix(c.shown, "v") || !slices.Equal(d.Adapter, []string{"reads_hardening"}) {
			t.Fatalf("%s: %+v", c.shown, d)
		}
		if !slices.IsSorted(d.Capabilities) || !slices.Contains(d.Capabilities, "expires_grants") ||
			slices.Contains(d.Capabilities, "records_sessions") {
			t.Fatalf("%s: capabilities %v", c.shown, d.Capabilities)
		}
		if got := slices.Contains(d.Capabilities, "ends_sessions_on_revoke"); got != c.ends {
			t.Fatalf("%s: ends_sessions_on_revoke %v, want %v", c.shown, got, c.ends)
		}
	}
}

// Without a version (a token Warpgate does not take) there is no declaration, and the error says what to check.
func TestNoVersionNoDeclaration(t *testing.T) {
	w := fakes.NewWarpgate("tok", nil)
	srv := httptest.NewTLSServer(w.Handler())
	defer srv.Close()
	b := warpgate.Bastion{C: &warpgate.Client{Base: srv.URL + "/@warpgate/admin/api", Token: "wrong", HTTP: srv.Client()}}
	if _, err := b.Declare(context.Background()); err == nil {
		t.Fatal("declared without a version")
	}
}

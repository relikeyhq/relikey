// SPDX-License-Identifier: EUPL-1.2

package warpgate

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveWarpgateTargets applies a targets file to a real Warpgate twice, so the calls of the targets command (roles,
// targets, their roles, known hosts, own keys) are checked against the real API and not only against the fake. The
// same variables and runner as TestLiveWarpgate; it removes the target, role and host key it made (relikey-live-*).
func TestLiveWarpgateTargets(t *testing.T) {
	url, token := os.Getenv("RELIKEY_LIVE_WARPGATE_URL"), os.Getenv("RELIKEY_LIVE_WARPGATE_TOKEN")
	if url == "" || token == "" {
		t.Skip("RELIKEY_LIVE_WARPGATE_URL and RELIKEY_LIVE_WARPGATE_TOKEN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := &Client{Base: url, Token: token, HTTP: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} //nolint:gosec // local throwaway, as TestLiveWarpgate
	spec := TargetSpec{Name: "relikey-live-target", Role: "relikey-live-target-role",
		SSH: SSH{Host: "192.0.2.10", Port: 22, Username: "liveuser"},
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}
	t.Cleanup(func() {
		bg := context.Background()
		var ts []Target
		_ = c.do(bg, http.MethodGet, "/targets", nil, &ts)
		for _, x := range ts {
			if x.Name == spec.Name {
				_ = c.do(bg, http.MethodDelete, "/targets/"+x.ID, nil, nil)
			}
		}
		rs, _ := c.Roles(bg)
		for _, r := range rs {
			if r.Name == spec.Role {
				_ = c.do(bg, http.MethodDelete, "/role/"+r.ID, nil, nil)
			}
		}
		var kh []struct {
			ID   string `json:"id"`
			Host string `json:"host"`
		}
		_ = c.do(bg, http.MethodGet, "/ssh/known-hosts", nil, &kh)
		for _, k := range kh {
			if k.Host == spec.SSH.Host {
				_ = c.do(bg, http.MethodDelete, "/ssh/known-hosts/"+k.ID, nil, nil)
			}
		}
	})
	var out bytes.Buffer
	keys, err := c.ApplyTargets(ctx, []TargetSpec{spec}, &out)
	if err != nil {
		t.Fatalf("first apply: %v\n%s", err, out.String())
	}
	for _, want := range []string{"role relikey-live-target-role: created", "target relikey-live-target: created",
		"role relikey-live-target-role bound", "host key pinned (ssh-ed25519)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("first apply: no %q in\n%s", want, out.String())
		}
	}
	if len(keys) == 0 || !strings.HasPrefix(keys[0], "ssh-") {
		t.Fatalf("Warpgate's client keys: %v", keys)
	}
	out.Reset()
	if _, err := c.ApplyTargets(ctx, []TargetSpec{spec}, &out); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "target relikey-live-target: kept (updated to the file)" {
		t.Fatalf("the second apply changed more than the target's settings:\n%s", got)
	}
	t.Logf("applied twice on the real Warpgate; client keys %d", len(keys))
}

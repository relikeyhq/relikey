// SPDX-License-Identifier: EUPL-1.2

package warpgate_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/warpgate"
)

var plc = warpgate.TargetSpec{Name: "plc-ssh", Role: "plc-operators",
	SSH: warpgate.SSH{Host: "10.0.0.5", Username: "plcuser"}, HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlcHostKey"}

// The targets file makes the role, the target, the binding and the pinned host key; a second run changes nothing
// but the target's own settings, and both return Warpgate's client keys.
func TestTargetsApplyAndStayApplied(t *testing.T) {
	w := fakes.NewWarpgate("tok", nil)
	srv := httptest.NewTLSServer(w.Handler())
	defer srv.Close()
	c := &warpgate.Client{Base: srv.URL + "/@warpgate/admin/api", Token: "tok", HTTP: srv.Client()}
	var out bytes.Buffer
	keys, err := c.ApplyTargets(context.Background(), []warpgate.TargetSpec{plc}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"role plc-operators: created", "target plc-ssh: created (plcuser@10.0.0.5:22)",
		"target plc-ssh: role plc-operators bound", "target plc-ssh: host key pinned (ssh-ed25519)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("first run: no %q in\n%s", want, out.String())
		}
	}
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "ssh-ed25519 ") {
		t.Fatalf("client keys %v", keys)
	}
	out.Reset()
	if _, err := c.ApplyTargets(context.Background(), []warpgate.TargetSpec{plc}, &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "target plc-ssh: kept (updated to the file)" {
		t.Fatalf("second run changed more than the target's settings:\n%s", got)
	}
	roles, err := c.Roles(context.Background())
	if err != nil || len(roles) != 1 {
		t.Fatalf("roles %v %v: the second run made another", roles, err)
	}
}

// A target without its host key is refused before anything is sent.
func TestATargetWithoutHostKeyChangesNothing(t *testing.T) {
	w := fakes.NewWarpgate("tok", nil)
	srv := httptest.NewTLSServer(w.Handler())
	defer srv.Close()
	c := &warpgate.Client{Base: srv.URL + "/@warpgate/admin/api", Token: "tok", HTTP: srv.Client()}
	bad := plc
	bad.HostKey = ""
	_, err := c.ApplyTargets(context.Background(), []warpgate.TargetSpec{bad}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "host_key is missing") || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("err %v", err)
	}
	if w.Requests != 0 {
		t.Fatalf("%d requests before the refusal", w.Requests)
	}
}

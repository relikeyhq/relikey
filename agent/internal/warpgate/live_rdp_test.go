// SPDX-License-Identifier: EUPL-1.2

package warpgate

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestLiveWarpgateRDP holds a real RDP session through a real Warpgate and does what the agent does when a lease
// ends: the role is revoked and the session closed through the adapter. It checks what the agent's plan relies on
// (apply.Compute): the session is listed under its user and names the RDP target it reaches, so a lease that narrows
// or a session cap can find it; closing it ends it; and the session is recorded. Skipped unless the live settings of
// TestLiveWarpgate are set together with RELIKEY_LIVE_RDP_TARGET (the RDP host as Warpgate reaches it),
// RELIKEY_LIVE_RDP_TARGET_PASSWORD (its account rk's password) and RELIKEY_LIVE_RDP_CLIENT (a command as a JSON array of strings, that holds one
// RDP session through Warpgate for RDP_USER and RDP_PASSWORD from its environment, and prints an id; run with "stop
// ID" it ends the client, with "running ID" it prints true or false). tools/warpgate_live.py --rdp runs it.
func TestLiveWarpgateRDP(t *testing.T) {
	url, token := os.Getenv("RELIKEY_LIVE_WARPGATE_URL"), os.Getenv("RELIKEY_LIVE_WARPGATE_TOKEN")
	host, hostPW, client := os.Getenv("RELIKEY_LIVE_RDP_TARGET"), os.Getenv("RELIKEY_LIVE_RDP_TARGET_PASSWORD"),
		os.Getenv("RELIKEY_LIVE_RDP_CLIENT")
	if url == "" || token == "" || host == "" || hostPW == "" || client == "" {
		t.Skip("the live Warpgate and RDP settings are not set (tools/warpgate_live.py --rdp)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := &Client{Base: url, Token: token, HTTP: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} //nolint:gosec // local throwaway, as TestLiveWarpgate
	b := Bastion{C: c}

	// The installer's part: an RDP target and the role that reaches it.
	var target struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/targets", map[string]any{"name": "relikey-live-rdp", "options": map[string]any{
		"kind": "Rdp", "host": host, "port": 3389, "username": "rk", "auth": map[string]any{"kind": "Password", "password": hostPW},
		"verify_tls": false, "compression": "remotefx", "interactive_logon": false, "tls_security": "Tls12"},
		"ticket_requests_disabled": true, "ticket_require_approval": false, "require_approval": false}, &target); err != nil {
		t.Fatalf("create the RDP target: %v", err)
	}
	t.Cleanup(func() { _ = c.do(context.Background(), http.MethodDelete, "/targets/"+target.ID, nil, nil) })
	var role Role
	if err := c.do(ctx, http.MethodPost, "/roles", map[string]string{"name": "relikey-live-rdp-role"}, &role); err != nil {
		t.Fatalf("create role: %v", err)
	}
	t.Cleanup(func() { _ = c.do(context.Background(), http.MethodDelete, "/role/"+role.ID, nil, nil) })
	if err := c.do(ctx, http.MethodPost, "/targets/"+target.ID+"/roles/"+role.ID, nil, nil); err != nil {
		t.Fatalf("give the role the target: %v", err)
	}

	// The lease: an account, a password the person signs in with, and the role until the lease ends.
	acct, err := b.CreateAccount(ctx, "relikey-live-rdp-ann", "relikey-managed: live RDP test")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = b.DeleteAccount(context.Background(), acct.ID) })
	pwBytes := make([]byte, 18)
	_, _ = rand.Read(pwBytes)
	pw := hex.EncodeToString(pwBytes)
	if err := c.do(ctx, http.MethodPost, "/users/"+acct.ID+"/credentials/passwords", map[string]string{"password": pw}, nil); err != nil {
		t.Fatalf("password credential: %v", err)
	}
	if err := b.Grant(ctx, acct.ID, role.ID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("grant: %v", err)
	}

	var cmd []string
	if err := json.Unmarshal([]byte(client), &cmd); err != nil || len(cmd) == 0 {
		t.Fatalf("RELIKEY_LIVE_RDP_CLIENT: a JSON array of strings, the command and its arguments (%v)", err)
	}
	run := func(args ...string) *exec.Cmd { return exec.CommandContext(ctx, cmd[0], append(cmd[1:], args...)...) } //nolint:gosec // the test's own client, from its environment
	running := func(cid string) bool {
		r, _ := run("running", cid).Output()
		return strings.TrimSpace(string(r)) == "true"
	}
	// hold starts a client and returns it with its session as the agent sees it, once Warpgate has reached the target
	// and the client has stayed up a few seconds (so a cut later is the test's doing, not the client's).
	hold := func() (string, Session) {
		t.Helper()
		start := run()
		start.Env = append(os.Environ(), "RDP_USER=relikey-live-rdp-ann:relikey-live-rdp", "RDP_PASSWORD="+pw)
		out, err := start.Output()
		if err != nil {
			t.Fatalf("start the RDP client: %v", err)
		}
		cid := strings.TrimSpace(string(out))
		t.Cleanup(func() { _ = exec.Command(cmd[0], append(cmd[1:], "stop", cid)...).Run() }) //nolint:gosec // as run
		for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
			ss, err := c.ActiveSessions(ctx)
			if err != nil {
				t.Fatalf("active sessions: %v", err)
			}
			for _, s := range ss {
				if s.UserID != acct.ID || len(s.TargetSessions) == 0 {
					continue
				}
				if s.TargetSessions[0].TargetID != target.ID || s.Username != "relikey-live-rdp-ann" {
					t.Fatalf("the session names target %s and user %q, want %s and relikey-live-rdp-ann",
						s.TargetSessions[0].TargetID, s.Username, target.ID)
				}
				time.Sleep(5 * time.Second)
				if !running(cid) {
					t.Fatal("the RDP client stopped by itself within 5 s of its session: nothing below would prove a cut")
				}
				return cid, s
			}
		}
		ss, _ := c.ActiveSessions(ctx)
		t.Fatalf("no RDP session of %s naming a target within 90 s: the agent could not narrow or cap it (sessions: %+v)",
			acct.ID, ss)
		return "", Session{}
	}
	cut := func(cid, sid, by string) {
		t.Helper()
		for end := time.Now().Add(30 * time.Second); running(cid); time.Sleep(time.Second) {
			if time.Now().After(end) {
				t.Fatalf("the RDP client still runs 30 s after %s", by)
			}
		}
		ss, err := b.ActiveSessions(ctx)
		if err != nil {
			t.Fatalf("active sessions: %v", err)
		}
		for _, s := range ss {
			if s.ID == sid {
				t.Fatalf("the RDP session is still active after %s", by)
			}
		}
	}

	// The lease ends, in apply's order: the session is closed, then the role revoked (a session already gone is
	// not found, which apply ignores).
	cid, sess := hold()
	if err := b.CloseSession(ctx, sess.ID); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := b.Revoke(ctx, acct.ID, role.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	cut(cid, sess.ID, "its session was closed")

	// Warpgate's own part: revoking the role alone also ends a live RDP session (a second layer under apply's close).
	if err := b.Grant(ctx, acct.ID, role.ID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("grant again: %v", err)
	}
	cid2, sess2 := hold()
	if err := b.Revoke(ctx, acct.ID, role.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	cut(cid2, sess2.ID, "its role was revoked")

	// Recorded as a desktop session.
	var recs []struct {
		Kind string `json:"kind"`
	}
	if err := c.do(ctx, http.MethodGet, "/sessions/"+sess.ID+"/recordings", nil, &recs); err != nil {
		t.Fatalf("recordings: %v", err)
	}
	if len(recs) == 0 || recs[0].Kind != "Desktop" {
		t.Fatalf("recordings %+v, want a Desktop recording", recs)
	}
}

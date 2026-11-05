// SPDX-License-Identifier: EUPL-1.2

package warpgate

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"
)

// TestLiveWarpgate drives every admin API call the adapter makes against a real Warpgate, so a Warpgate upgrade is
// checked against the real API and not only against the fake. Skipped unless RELIKEY_LIVE_WARPGATE_URL (the admin API
// base, https://127.0.0.1:PORT/@warpgate/admin/api) and RELIKEY_LIVE_WARPGATE_TOKEN (its WARPGATE_ADMIN_TOKEN, run
// with --enable-admin-token) are set; tools/warpgate_live.sh runs it on a throwaway Warpgate in a container. It makes
// and removes one role and one user, both named relikey-live-*.
func TestLiveWarpgate(t *testing.T) {
	url, token := os.Getenv("RELIKEY_LIVE_WARPGATE_URL"), os.Getenv("RELIKEY_LIVE_WARPGATE_TOKEN")
	if url == "" || token == "" {
		t.Skip("RELIKEY_LIVE_WARPGATE_URL and RELIKEY_LIVE_WARPGATE_TOKEN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// A throwaway Warpgate's own certificate: the test checks the API, not the pin (httpx pins it in the agent).
	c := &Client{Base: url, Token: token, HTTP: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} //nolint:gosec // local throwaway, see above
	b := Bastion{C: c}

	var role Role
	if err := c.do(ctx, http.MethodPost, "/roles", map[string]string{"name": "relikey-live-role"}, &role); err != nil {
		t.Fatalf("create role: %v", err)
	}
	t.Cleanup(func() { _ = c.do(context.Background(), http.MethodDelete, "/role/"+role.ID, nil, nil) })
	roles, err := c.Roles(ctx)
	if err != nil || !slices.ContainsFunc(roles, func(r Role) bool { return r.ID == role.ID }) {
		t.Fatalf("roles %v, %v", roles, err)
	}

	u, err := c.CreateUser(ctx, "relikey-live-ann", "relikey-managed: live test")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _ = c.DeleteUser(context.Background(), u.ID) })
	users, err := c.Users(ctx)
	if err != nil || !slices.ContainsFunc(users, func(x User) bool { return x.ID == u.ID && x.Description == "relikey-managed: live test" }) {
		t.Fatalf("users: %v", err)
	}

	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := c.AddUserRole(ctx, u.ID, role.ID, until); err != nil {
		t.Fatalf("grant: %v", err)
	}
	assigned := func() *RoleAssignment {
		as, err := c.UserRoles(ctx, u.ID)
		if err != nil {
			t.Fatalf("user roles: %v", err)
		}
		for i := range as {
			if as[i].ID == role.ID {
				return &as[i]
			}
		}
		return nil
	}
	if a := assigned(); a == nil || !a.IsActive || a.ExpiresAt == nil || !a.ExpiresAt.Equal(until) {
		t.Fatalf("after the grant: %+v, want active until %s", a, until)
	}
	later := until.Add(time.Hour)
	if err := c.SetUserRoleExpiry(ctx, u.ID, role.ID, later); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	if a := assigned(); a == nil || a.ExpiresAt == nil || !a.ExpiresAt.Equal(later) {
		t.Fatalf("after the new expiry: %+v, want %s", a, later)
	}

	if err := c.AddSSOCredential(ctx, u.ID, "keycloak", "ann@example.test"); err != nil {
		t.Fatalf("add SSO credential: %v", err)
	}
	sso, err := c.SSOCredentials(ctx, u.ID)
	if err != nil || len(sso) != 1 || sso[0].Email != "ann@example.test" || sso[0].Provider != "keycloak" {
		t.Fatalf("SSO credentials %+v, %v", sso, err)
	}
	if err := c.DeleteSSOCredential(ctx, u.ID, sso[0].ID); err != nil {
		t.Fatalf("delete SSO credential: %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	key := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(sshWire("ssh-ed25519", pub))
	if err := c.AddPublicKey(ctx, u.ID, "relikey-live", key); err != nil {
		t.Fatalf("add public key: %v", err)
	}
	keys, err := c.PublicKeys(ctx, u.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("public keys %+v, %v", keys, err)
	}
	if err := c.DeletePublicKey(ctx, u.ID, keys[0].ID); err != nil {
		t.Fatalf("delete public key: %v", err)
	}
	for _, kind := range OtherCredentialKinds {
		if _, err := c.OtherCredentials(ctx, u.ID, kind); err != nil {
			t.Fatalf("list %s: %v", kind, err)
		}
	}

	if err := c.RemoveUserRole(ctx, u.ID, role.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if a := assigned(); a != nil && a.IsActive {
		t.Fatalf("still active after the revoke: %+v", a)
	}

	if _, err := c.ActiveSessions(ctx); err != nil {
		t.Fatalf("active sessions: %v", err)
	}
	if err := b.Harden(ctx); err != nil {
		t.Fatalf("harden: %v", err)
	}
	h, err := b.Hardening(ctx)
	if err != nil || len(h.Weaknesses()) != 0 {
		t.Fatalf("after hardening: %+v %v, %v", h, h.Weaknesses(), err)
	}

	if err := c.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if users, _ := c.Users(ctx); slices.ContainsFunc(users, func(x User) bool { return x.ID == u.ID }) {
		t.Fatal("the user is still there")
	}
}

// sshWire is the SSH wire form of a public key: two length-prefixed strings.
func sshWire(kind string, key []byte) []byte {
	var out []byte
	for _, part := range [][]byte{[]byte(kind), key} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(part)))
		out = append(out, part...)
	}
	return out
}

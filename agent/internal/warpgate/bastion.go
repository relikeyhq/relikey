// SPDX-License-Identifier: EUPL-1.2

package warpgate

import (
	"context"
	"fmt"
	"time"

	"relikey/agent/internal/bastion"
)

// Bastion adapts Warpgate's admin API to the bastion role (decision 0023): Warpgate's users are accounts, its role
// assignments with expires_at are grants (removed ones stay listed as inactive: Warpgate's soft delete), its SSO
// credentials are identities and its public-key credentials are keys.
type Bastion struct{ C *Client }

var _ bastion.Admin = Bastion{}

// nf maps Warpgate's 404 to the role's not-found, keeping Warpgate's message.
func nf(err error) error {
	if NotFound(err) {
		return fmt.Errorf("%w: %v", bastion.ErrNotFound, err)
	}
	return err
}

func (b Bastion) Accounts(ctx context.Context) ([]bastion.Account, error) {
	us, err := b.C.Users(ctx)
	out := make([]bastion.Account, 0, len(us))
	for _, u := range us {
		out = append(out, bastion.Account{ID: u.ID, Name: u.Username, Description: u.Description})
	}
	return out, nf(err)
}

func (b Bastion) CreateAccount(ctx context.Context, name, description string) (bastion.Account, error) {
	u, err := b.C.CreateUser(ctx, name, description)
	return bastion.Account{ID: u.ID, Name: u.Username, Description: u.Description}, nf(err)
}

func (b Bastion) DeleteAccount(ctx context.Context, id string) error {
	return nf(b.C.DeleteUser(ctx, id))
}

func roles(rs []Role) []bastion.Role {
	out := make([]bastion.Role, 0, len(rs))
	for _, r := range rs {
		out = append(out, bastion.Role{ID: r.ID, Name: r.Name})
	}
	return out
}

func (b Bastion) Roles(ctx context.Context) ([]bastion.Role, error) {
	rs, err := b.C.Roles(ctx)
	return roles(rs), nf(err)
}

func (b Bastion) RoleTargets(ctx context.Context, roleID string) ([]bastion.Target, error) {
	ts, err := b.C.RoleTargets(ctx, roleID)
	out := make([]bastion.Target, 0, len(ts))
	for _, t := range ts {
		out = append(out, bastion.Target{ID: t.ID, Name: t.Name})
	}
	return out, nf(err)
}

func (b Bastion) TargetRoles(ctx context.Context, targetID string) ([]bastion.Role, error) {
	rs, err := b.C.TargetRoles(ctx, targetID)
	return roles(rs), nf(err)
}

func (b Bastion) Grants(ctx context.Context, accountID string) ([]bastion.Grant, error) {
	ras, err := b.C.UserRoles(ctx, accountID)
	out := make([]bastion.Grant, 0, len(ras))
	for _, ra := range ras {
		out = append(out, bastion.Grant{RoleID: ra.ID, Role: ra.Name, Expires: ra.ExpiresAt, Active: ra.IsActive})
	}
	return out, nf(err)
}

func (b Bastion) Grant(ctx context.Context, accountID, roleID string, expires time.Time) error {
	return nf(b.C.AddUserRole(ctx, accountID, roleID, expires))
}

func (b Bastion) SetGrantExpiry(ctx context.Context, accountID, roleID string, expires time.Time) error {
	return nf(b.C.SetUserRoleExpiry(ctx, accountID, roleID, expires))
}

func (b Bastion) Revoke(ctx context.Context, accountID, roleID string) error {
	return nf(b.C.RemoveUserRole(ctx, accountID, roleID))
}

func (b Bastion) Identities(ctx context.Context, accountID string) ([]bastion.Identity, error) {
	cs, err := b.C.SSOCredentials(ctx, accountID)
	out := make([]bastion.Identity, 0, len(cs))
	for _, c := range cs {
		out = append(out, bastion.Identity{ID: c.ID, Provider: c.Provider, Email: c.Email})
	}
	return out, nf(err)
}

func (b Bastion) AddIdentity(ctx context.Context, accountID, provider, email string) error {
	return nf(b.C.AddSSOCredential(ctx, accountID, provider, email))
}

func (b Bastion) RemoveIdentity(ctx context.Context, accountID, id string) error {
	return nf(b.C.DeleteSSOCredential(ctx, accountID, id))
}

func (b Bastion) Keys(ctx context.Context, accountID string) ([]bastion.Key, error) {
	ks, err := b.C.PublicKeys(ctx, accountID)
	out := make([]bastion.Key, 0, len(ks))
	for _, k := range ks {
		out = append(out, bastion.Key{ID: k.ID, Label: k.Label, OpenSSH: k.OpenSSHPublicKey})
	}
	return out, nf(err)
}

func (b Bastion) AddKey(ctx context.Context, accountID, label, openssh string) error {
	return nf(b.C.AddPublicKey(ctx, accountID, label, openssh))
}

func (b Bastion) RemoveKey(ctx context.Context, accountID, id string) error {
	return nf(b.C.DeletePublicKey(ctx, accountID, id))
}

func (b Bastion) ActiveSessions(ctx context.Context) ([]bastion.Session, error) {
	ss, err := b.C.ActiveSessions(ctx)
	out := make([]bastion.Session, 0, len(ss))
	for _, s := range ss {
		ts := make([]bastion.TargetSession, 0, len(s.TargetSessions))
		for _, t := range s.TargetSessions {
			ts = append(ts, bastion.TargetSession{TargetID: t.TargetID, Started: t.Started, Ended: t.Ended})
		}
		out = append(out, bastion.Session{ID: s.ID, Account: s.Username, AccountID: s.UserID, Targets: ts})
	}
	return out, nf(err)
}

func (b Bastion) CloseSession(ctx context.Context, id string) error {
	return nf(b.C.CloseSession(ctx, id))
}

func (b Bastion) Hardening(ctx context.Context) (bastion.Hardening, error) {
	p, err := b.C.Parameters(ctx)
	h := bastion.Hardening{SelfServiceCredentials: p.AllowOwnCredentialManagement, PasswordSSH: p.SSHClientAuthPassword}
	if p.MaxAPITokenDurationSeconds != nil {
		h.APITokenMaxSeconds = *p.MaxAPITokenDurationSeconds
	}
	return h, nf(err)
}

func (b Bastion) Harden(ctx context.Context) error {
	return nf(b.C.SetParameters(ctx, map[string]any{"allow_own_credential_management": false,
		"ssh_client_auth_password": false, "max_api_token_duration_seconds": bastion.APITokenMax}))
}

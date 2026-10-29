// SPDX-License-Identifier: EUPL-1.2

// Package bastion is the bastion role as the agent sees it (decisions 0016, 0023): the reference model of a bastion
// that grants access by expiring roles. Accounts hold grants of roles; a role reaches targets; an account signs in with
// identities (single sign-on) or keys; sessions run on targets. The agent's plan is computed in these terms only.
// Adapters (Warpgate is the reference one) convert a product's admin API to this model; a product with another model
// needs an adapter that maps it, and what cannot be mapped is a stated gap (0016's matrix).
package bastion

import (
	"context"
	"errors"
	"time"
)

// Account is a person's account on the bastion.
type Account struct {
	ID          string
	Name        string
	Description string // the agent marks the accounts it manages here
}

// Role is a named set of targets an account may reach while it holds the role.
type Role struct {
	ID   string
	Name string
}

// Grant is an account's hold on a role, until Expires (nil: no expiry). An inactive grant is one the bastion keeps
// after removal (a soft delete); Active is false then.
type Grant struct {
	RoleID  string
	Role    string
	Expires *time.Time
	Active  bool
}

// Identity binds an account to a sign-in at an identity provider (decision 0010).
type Identity struct {
	ID       string
	Provider string
	Email    string
}

// Key is an SSH public key an account signs in with (visit leases, C-06).
type Key struct {
	ID      string
	Label   string
	OpenSSH string
}

// Target is a system the bastion fronts.
type Target struct {
	ID   string
	Name string
}

// TargetSession is one target within a session.
type TargetSession struct {
	TargetID string
	Started  time.Time
	Ended    *time.Time
}

// Session is an open session on the bastion.
type Session struct {
	ID        string
	Account   string // the account's name
	AccountID string
	Targets   []TargetSession
}

// Admin is what the agent needs from a bastion. Every call is idempotent from the caller's side: a removal of
// something already gone returns an error for which NotFound is true, and the agent treats it as done.
type Admin interface {
	Accounts(ctx context.Context) ([]Account, error)
	CreateAccount(ctx context.Context, name, description string) (Account, error)
	DeleteAccount(ctx context.Context, id string) error

	Roles(ctx context.Context) ([]Role, error)
	RoleTargets(ctx context.Context, roleID string) ([]Target, error)
	TargetRoles(ctx context.Context, targetID string) ([]Role, error)

	Grants(ctx context.Context, accountID string) ([]Grant, error)
	Grant(ctx context.Context, accountID, roleID string, expires time.Time) error
	SetGrantExpiry(ctx context.Context, accountID, roleID string, expires time.Time) error
	Revoke(ctx context.Context, accountID, roleID string) error

	Identities(ctx context.Context, accountID string) ([]Identity, error)
	AddIdentity(ctx context.Context, accountID, provider, email string) error
	RemoveIdentity(ctx context.Context, accountID, id string) error

	Keys(ctx context.Context, accountID string) ([]Key, error)
	AddKey(ctx context.Context, accountID, label, openssh string) error
	RemoveKey(ctx context.Context, accountID, id string) error

	ActiveSessions(ctx context.Context) ([]Session, error)
	CloseSession(ctx context.Context, id string) error
}

// ErrNotFound is what an adapter wraps when the bastion says a thing does not exist.
var ErrNotFound = errors.New("not found on the bastion")

// NotFound reports whether err means the thing does not exist.
func NotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// Transient reports whether a failed read may succeed if asked again at once: not a cancelled or timed-out context
// (the tick's budget or a shutdown), not a thing that does not exist, and not an error that says of itself it is
// permanent (an adapter's refusal answers false to Transient() bool, such as a rejected token). Anything else, a
// transport error or an overloaded bastion, may pass.
func Transient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || NotFound(err) {
		return false
	}
	var t interface{ Transient() bool }
	if errors.As(err, &t) {
		return t.Transient()
	}
	return true
}

// Hardening is the bastion settings ReliKey depends on: no self-service credentials (a person could add a password,
// a key or a token the broker never sees, or make their account unreadable to the agent), no password SSH, and API
// tokens that expire (stack attack 2026-10-25, E1 and E4).
type Hardening struct {
	SelfServiceCredentials bool
	PasswordSSH            bool
	APITokenMaxSeconds     int64 // 0: no limit
}

// APITokenMax is the longest API token the bastion may issue.
const APITokenMax = 3600

// Weaknesses names what h allows that ReliKey does not, empty when none.
func (h Hardening) Weaknesses() []string {
	var w []string
	if h.SelfServiceCredentials {
		w = append(w, "self-service credentials")
	}
	if h.PasswordSSH {
		w = append(w, "password SSH")
	}
	if h.APITokenMaxSeconds <= 0 || h.APITokenMaxSeconds > APITokenMax {
		w = append(w, "API tokens without a one-hour limit")
	}
	return w
}

// Hardener is a bastion whose hardening the agent can read and restore. Optional: a bastion without it is reported
// as unchecked.
type Hardener interface {
	Hardening(ctx context.Context) (Hardening, error)
	Harden(ctx context.Context) error // sets every setting to what ReliKey requires
}

// SPDX-License-Identifier: EUPL-1.2

// Package apply turns the leases and visit leases live now into the bastion's state (the bastion role, decision 0023): a plan computed from
// what is observed, executed in a fixed order (sessions closed, then removals, then
// grants), every step idempotent so a crash or a retry converges. The plan is a value:
// shadow mode reports it without executing (the canary), and tests check it directly.
package apply

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"

	"relikey/agent/internal/bastion"
	"relikey/agent/internal/kcedge"
)

// Marker is the description of every bastion account the agent manages. Users without
// it (installers, break-glass, anything an operator made) are never touched.
const Marker = "relikey-managed: do not edit, the edge agent owns this user"

// Desired is what the live leases ask of the bastion.
type Desired struct {
	Users map[string]*DesiredUser // by username
	Drift []string                // what cannot be applied, and why
	// Now is the trusted moment the leases were evaluated at; with it, sessions longer
	// than their leases allow are closed. Zero leaves session length unchecked.
	Now time.Time
	// Governed is the clerk's signed catalogue of the roles it governs on this edge (KeyClerk decision 0025); nil when
	// the bundle carries none, which is never "none governed".
	Governed *[]string
}

type DesiredUser struct {
	Email string
	Roles map[string]time.Time // role name -> when the last lease granting it ends
	// MaxSession is the longest a session may run on a target the role reaches: the
	// most generous live lease for that role; 0 means no cap (max_session_hours unset).
	MaxSession map[string]time.Duration
	// Keys are the SSH public keys visit leases install, normalised to "type base64".
	Keys map[string]bool
	// VisitTargets holds, for a role only visit leases grant, the target names every one
	// of those leases allows: the role may be assigned only if it reaches no other target
	// (C-06; a bastion role grants every target bound to it).
	VisitTargets map[string][]string
	// LeaseTargets holds, for each role an ordinary lease grants, the targets those leases name: the role may be
	// assigned only if every target it reaches is one of them or of VisitTargets, since a bastion role grants every
	// target bound to it and the ceiling checks only the lease's target (AG-11, decided "agent enforces, fail
	// closed"; stack attack 2026-10-25, E3).
	LeaseTargets map[string][]string
}

// VisitKeyTypes are the key types a visit lease may install: hardware-held keys
// (C-06; sk-ssh-ed25519 once U-01 lands) and ed25519.
var VisitKeyTypes = []string{"sk-ssh-ed25519@openssh.com", "ssh-ed25519"}

// FromLeases builds the desired state from leases alone.
func FromLeases(leases []kcedge.Lease) Desired { return FromLive(leases, nil) }

func newUser() *DesiredUser {
	return &DesiredUser{Roles: map[string]time.Time{}, MaxSession: map[string]time.Duration{}, Keys: map[string]bool{},
		LeaseTargets: map[string][]string{},
		VisitTargets: map[string][]string{}}
}

// FromLive builds the desired state from the live leases and visit leases. The SSO
// provider name is the edge's one provider (decision 0010).
func FromLive(leases []kcedge.Lease, visits []kcedge.VisitLease) Desired {
	d := Desired{Users: map[string]*DesiredUser{}}
	person, conflicted := map[string]string{}, map[string]bool{}
	leaseRoles := map[string]map[string]bool{} // username -> roles an ordinary lease grants
	for _, l := range leases {
		if l.Username == "" || l.Role == "" || l.Target == "" {
			d.Drift = append(d.Drift, fmt.Sprintf("lease %s names no username, role or target: not applied", l.LeaseID))
			continue
		}
		if p, seen := person[l.Username]; seen && p != l.Person {
			conflicted[l.Username] = true // two people under one name: neither gets it (AG-9)
			continue
		}
		person[l.Username] = l.Person
		u := d.Users[l.Username]
		if u == nil {
			u = newUser()
			d.Users[l.Username] = u
		}
		if leaseRoles[l.Username] == nil {
			leaseRoles[l.Username] = map[string]bool{}
		}
		leaseRoles[l.Username][l.Role] = true
		if !slices.Contains(u.LeaseTargets[l.Role], l.Target) {
			u.LeaseTargets[l.Role] = append(u.LeaseTargets[l.Role], l.Target)
		}
		switch {
		case l.Email == "":
			d.Drift = append(d.Drift, fmt.Sprintf("lease %s carries no e-mail: %s cannot sign in through SSO "+
				"(KeyClerk must send the verified e-mail, decision 0010)", l.LeaseID, l.Username))
		case u.Email == "":
			u.Email = l.Email
		case u.Email != l.Email:
			d.Drift = append(d.Drift, fmt.Sprintf("leases for %s carry different e-mails: the first (%s) is used", l.Username, u.Email))
		}
		limit := time.Duration(l.MaxSessionHours) * time.Hour
		if have, seen := u.MaxSession[l.Role]; !seen || (have != 0 && (limit == 0 || limit > have)) {
			u.MaxSession[l.Role] = limit // the most generous lease wins; 0 (no cap) beats any cap
		}
		if end := l.Ends; end.After(u.Roles[l.Role]) {
			u.Roles[l.Role] = end
		}
	}
	for _, v := range visits {
		if v.Username == "" || v.Role == "" {
			d.Drift = append(d.Drift, fmt.Sprintf("visit lease %s names no username or role: not applied", v.LeaseID))
			continue
		}
		key, why := normaliseKey(v.SSHKey)
		if why != "" {
			d.Drift = append(d.Drift, fmt.Sprintf("visit lease %s: %s: not applied", v.LeaseID, why))
			continue
		}
		if len(v.Targets) == 0 {
			d.Drift = append(d.Drift, fmt.Sprintf("visit lease %s names no target: not applied", v.LeaseID))
			continue
		}
		if p, seen := person[v.Username]; seen && p != v.Person {
			conflicted[v.Username] = true
			continue
		}
		person[v.Username] = v.Person
		u := d.Users[v.Username]
		if u == nil {
			u = newUser()
			d.Users[v.Username] = u
		}
		u.Keys[key] = true
		if v.Ends.After(u.Roles[v.Role]) {
			u.Roles[v.Role] = v.Ends
		}
		if _, seen := u.MaxSession[v.Role]; !seen {
			u.MaxSession[v.Role] = 0 // a visit ends at its window; its sessions close with the role
		}
		if have, seen := u.VisitTargets[v.Role]; seen {
			u.VisitTargets[v.Role] = slices.DeleteFunc(have, func(t string) bool { return !slices.Contains(v.Targets, t) })
		} else {
			u.VisitTargets[v.Role] = slices.Clone(v.Targets)
		}
	}
	for name, roles := range leaseRoles {
		if u := d.Users[name]; u != nil {
			for r := range roles {
				delete(u.VisitTargets, r) // an ordinary lease grants the whole role
			}
		}
	}
	for name := range conflicted {
		delete(d.Users, name)
		d.Drift = append(d.Drift, fmt.Sprintf("leases for different people share the username %s: none applied "+
			"(usernames must be unique per person)", name))
	}
	slices.Sort(d.Drift)
	return d
}

// Observed is what the bastion holds, as far as the agent cares.
type Observed struct {
	Roles       map[string]string // role name -> id
	Managed     map[string]*ObservedUser
	Unmanaged   map[string]bool     // usernames the agent must not touch
	TargetRoles map[string][]string // target id -> role names
	// Orphans are open sessions whose account no longer exists on the bastion (deleted while
	// signing in, or after a close failed): no one may own them, so they are closed.
	Orphans []bastion.Session
	// Unreadable are managed users whose roles or credentials could not be read this tick, with what was read
	// without them: the id and the sessions. With a live lease nothing is planned for them (AG-4); without one they
	// are closed and deleted all the same, which needs no per-user read, so a person cannot outlive a lease by making
	// their account unreadable (stack attack 2026-10-25, E1).
	Unreadable      map[string]bool
	UnreadableUsers map[string]*ObservedUser
	// RoleTargets are the target names each role reaches, read for the roles visit
	// leases grant (ReadRoleTargets); a configured role missing here is not assigned
	// for a visit.
	RoleTargets map[string][]string
	// Rogue are the unmanaged accounts holding a governed role now, with those roles (ReadUnmanagedGrants): reported,
	// never changed (full-stack run 2, finding 8).
	Rogue map[string][]string
	// RoguePartial: not every source of governed roles could be read this tick, so an absence proves nothing: new
	// findings are reported, none is resolved. RogueUnchecked: accounts whose roles could not be read this tick keep
	// their last reported state. A nil Rogue means no check ran at all (red team of 2026-10-25: no false "resolved").
	RoguePartial   bool
	RogueUnchecked map[string]bool
	// Notes are what this tick could not check, for the drift report.
	Notes []string
	// unmanagedIDs are the unmanaged accounts' ids, by name.
	unmanagedIDs map[string]string
}

type ObservedUser struct {
	ID    string
	Roles map[string]bastion.Grant // by role name
	SSO   []bastion.Identity
	Keys  []bastion.Key
	// Credentials are the account's passwords, one-time-password seeds and certificates: none is the lease's, so all
	// go, the ones made before the agent or behind its back too.
	Credentials []bastion.Credential
	Sessions    []bastion.Session
}

// Observe reads the bastion. Sessions are read for managed users only.
func Observe(ctx context.Context, bas bastion.Admin) (*Observed, error) {
	o := &Observed{Roles: map[string]string{}, Managed: map[string]*ObservedUser{}, Unmanaged: map[string]bool{},
		TargetRoles: map[string][]string{}, Unreadable: map[string]bool{}, UnreadableUsers: map[string]*ObservedUser{},
		unmanagedIDs: map[string]string{}}
	roles, err := bas.Roles(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		o.Roles[r.Name] = r.ID
	}
	users, err := bas.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	sessions, err := bas.ActiveSessions(ctx)
	if err != nil {
		return nil, err
	}
	// Sessions belong to users by id: a name filter can be case-insensitive (Warpgate's is) and
	// could hand another account's session to a managed user (AG-8).
	byUser := map[string][]bastion.Session{}
	exists := map[string]bool{}
	for _, u := range users {
		exists[u.ID] = true
	}
	for _, s := range sessions {
		if s.AccountID == "" && s.Account == "" && len(s.Targets) == 0 {
			continue // still signing in (an SSH out-of-band approval): no account yet, nothing granted (full-stack run 2)
		}
		if s.AccountID == "" || !exists[s.AccountID] {
			o.Orphans = append(o.Orphans, s)
			continue
		}
		byUser[s.AccountID] = append(byUser[s.AccountID], s)
	}
	for _, u := range users {
		if u.Description != Marker {
			o.Unmanaged[u.Name] = true
			o.unmanagedIDs[u.Name] = u.ID
			continue
		}
		ou := &ObservedUser{ID: u.ID, Roles: map[string]bastion.Grant{}}
		ras, err := bas.Grants(ctx, u.ID)
		if err == nil {
			ou.SSO, err = bas.Identities(ctx, u.ID)
		}
		if err == nil {
			ou.Keys, err = bas.Keys(ctx, u.ID)
		}
		if err == nil {
			ou.Credentials, err = bas.Credentials(ctx, u.ID)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			o.Unreadable[u.Name] = true
			o.UnreadableUsers[u.Name] = &ObservedUser{ID: u.ID, Roles: map[string]bastion.Grant{}, Sessions: byUser[u.ID]}
			continue
		}
		for _, ra := range ras {
			ou.Roles[ra.Role] = ra
		}
		ou.Sessions = byUser[u.ID]
		for _, s := range ou.Sessions {
			for _, ts := range s.Targets {
				if _, seen := o.TargetRoles[ts.TargetID]; seen || ts.Ended != nil {
					continue
				}
				trs, err := bas.TargetRoles(ctx, ts.TargetID)
				if err != nil && !bastion.NotFound(err) {
					return nil, err
				}
				names := []string{}
				for _, r := range trs {
					names = append(names, r.Name)
				}
				o.TargetRoles[ts.TargetID] = names
			}
		}
		o.Managed[u.Name] = ou
	}
	return o, nil
}

// ReadRoleTargets reads the targets of every role a visit lease grants. A role that
// cannot be read is left out, so its visits are not applied this tick.
func (o *Observed) ReadRoleTargets(ctx context.Context, bas bastion.Admin, d Desired) error {
	if o.RoleTargets == nil {
		o.RoleTargets = map[string][]string{}
	}
	for _, du := range d.Users {
		for role := range du.Roles {
			id, ok := o.Roles[role]
			if _, done := o.RoleTargets[role]; done || !ok {
				continue
			}
			ts, err := bas.RoleTargets(ctx, id)
			if err != nil {
				if ctx.Err() != nil {
					return err
				}
				continue
			}
			names := []string{}
			for _, t := range ts {
				names = append(names, t.Name)
			}
			o.RoleTargets[role] = names
		}
	}
	return nil
}

// normaliseKey checks an OpenSSH public key line and returns "type base64", or why it
// is refused: only VisitKeyTypes, and the blob must name the same type.
func normaliseKey(line string) (string, string) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return "", "the ssh key is not an OpenSSH public key line"
	}
	if !slices.Contains(VisitKeyTypes, f[0]) {
		return "", fmt.Sprintf("ssh key type %s is not allowed (only %s)", f[0], strings.Join(VisitKeyTypes, ", "))
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 4 {
		return "", "the ssh key is not valid base64"
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != f[0] {
		return "", "the ssh key's blob does not match its type"
	}
	return f[0] + " " + f[1], ""
}

// Kind orders actions: everything that takes access away runs first.
type Kind int

const (
	CloseSession Kind = iota
	RemoveRole
	DeleteSSO
	DeleteCredential
	DeleteUser
	DeleteKey
	CreateUser // grants from here on
	AddSSO
	AddKey
	AddRole
	SetExpiry
)

var kindNames = [...]string{"close-session", "remove-role", "delete-sso", "delete-credential", "delete-user",
	"delete-key", "create-user", "add-sso", "add-key", "add-role", "set-expiry"}

func (k Kind) String() string { return kindNames[k] }

// Grant reports whether the action gives access.
func (k Kind) Grant() bool { return k >= CreateUser }

// Action is one idempotent step.
type Action struct {
	Kind     Kind      `json:"-"`
	Name     string    `json:"kind"`
	Username string    `json:"username"`
	UserID   string    `json:"user_id,omitempty"`
	Role     string    `json:"role,omitempty"`
	RoleID   string    `json:"role_id,omitempty"`
	Expires  time.Time `json:"expires,omitzero"`
	Session  string    `json:"session,omitempty"`
	SSOID    string    `json:"sso_id,omitempty"`
	Email    string    `json:"email,omitempty"`
	KeyID    string    `json:"key_id,omitempty"`
	Key      string    `json:"key,omitempty"`
	// Credential is a password, one-time-password seed or certificate to remove (DeleteCredential).
	Credential bastion.Credential `json:"credential,omitzero"`
	Why        string             `json:"why"`
}

func (a Action) String() string {
	s := a.Name + " " + a.Username
	if a.Role != "" {
		s += " " + a.Role
	}
	if a.Session != "" {
		s += " session " + a.Session
	}
	return s + ": " + a.Why
}

// Plan is the ordered list of actions and what could not be planned.
type Plan struct {
	Actions []Action `json:"actions"`
	Drift   []string `json:"drift"`
}

// expirySlack: bastions store expiry in whole seconds (Warpgate does); a difference below this is no change.
const expirySlack = 2 * time.Second

// Compute is pure: the same desired and observed state always give the same plan.
func Compute(d Desired, o *Observed, provider string) Plan {
	p := Plan{Drift: slices.Clone(d.Drift)}
	add := func(a Action) { a.Name = a.Kind.String(); p.Actions = append(p.Actions, a) }
	for _, s := range o.Orphans {
		add(Action{Kind: CloseSession, Username: s.Account, Session: s.ID, Why: "its user no longer exists"})
	}

	d, visitDrift := narrowVisits(d, o)
	for _, name := range sortedKeys(o.Unreadable) {
		ou := o.UnreadableUsers[name]
		if d.Users[name] != nil || ou == nil {
			p.Drift = append(p.Drift, fmt.Sprintf("user %s could not be read this tick: nothing changed for it", name))
			continue
		}
		p.Drift = append(p.Drift, fmt.Sprintf("user %s could not be read this tick and has no live lease: closed and "+
			"deleted without reading it", name))
		for _, s := range ou.Sessions {
			add(Action{Kind: CloseSession, Username: name, UserID: ou.ID, Session: s.ID, Why: "no live lease (its details could not be read)"})
		}
		add(Action{Kind: DeleteUser, Username: name, UserID: ou.ID, Why: "no live lease (its details could not be read)"})
	}
	p.Drift = append(p.Drift, o.Notes...)
	for _, name := range sortedKeys(o.Rogue) {
		if len(o.Rogue[name]) > 0 {
			p.Drift = append(p.Drift, fmt.Sprintf("account %s is not managed by ReliKey but holds the governed role %s, "+
				"which only a lease grants: reported, not changed", name, strings.Join(o.Rogue[name], ", ")))
		}
	}
	p.Drift = append(p.Drift, visitDrift...)
	for _, name := range sortedKeys(o.Managed) {
		ou := o.Managed[name]
		du := d.Users[name]
		if du == nil {
			for _, s := range ou.Sessions {
				add(Action{Kind: CloseSession, Username: name, UserID: ou.ID, Session: s.ID, Why: "no live lease"})
			}
			// Roles and SSO go too: if a close fails, the delete waits (it would hide the session), and until then the
			// person must not be able to sign in again (stack attack 2026-10-25, E5).
			for _, role := range sortedKeys(ou.Roles) {
				if ou.Roles[role].Active {
					add(Action{Kind: RemoveRole, Username: name, UserID: ou.ID, Role: role, RoleID: ou.Roles[role].RoleID,
						Why: "no live lease"})
				}
			}
			for _, c := range ou.SSO {
				add(Action{Kind: DeleteSSO, Username: name, UserID: ou.ID, SSOID: c.ID, Email: c.Email, Why: "no live lease"})
			}
			for _, c := range ou.Credentials {
				add(Action{Kind: DeleteCredential, Username: name, UserID: ou.ID, Credential: c, Why: "no live lease"})
			}
			add(Action{Kind: DeleteUser, Username: name, UserID: ou.ID, Why: "no live lease"})
			continue
		}
		// A session may run only on a target one of the user's live roles reaches.
		for _, s := range ou.Sessions {
			for _, ts := range s.Targets {
				if ts.Ended != nil {
					continue
				}
				if !slices.ContainsFunc(o.TargetRoles[ts.TargetID], func(r string) bool { _, ok := du.Roles[r]; return ok }) {
					add(Action{Kind: CloseSession, Username: name, UserID: ou.ID, Session: s.ID,
						Why: "its target is no longer reached by a live lease"})
					break
				}
				if allowed := sessionCap(du, o.TargetRoles[ts.TargetID]); allowed > 0 && !d.Now.IsZero() &&
					!ts.Started.IsZero() && d.Now.Sub(ts.Started) > allowed {
					add(Action{Kind: CloseSession, Username: name, UserID: ou.ID, Session: s.ID,
						Why: fmt.Sprintf("it ran longer than its leases allow (%v)", allowed)})
					break
				}
			}
		}
		for _, role := range sortedKeys(ou.Roles) {
			if _, ok := du.Roles[role]; !ok && ou.Roles[role].Active {
				add(Action{Kind: RemoveRole, Username: name, UserID: ou.ID, Role: role, RoleID: ou.Roles[role].RoleID,
					Why: "no live lease grants it"})
			}
		}
		for _, c := range ou.SSO {
			if du.Email == "" || c.Email != du.Email || c.Provider != provider {
				add(Action{Kind: DeleteSSO, Username: name, UserID: ou.ID, SSOID: c.ID, Email: c.Email,
					Why: "not the lease's e-mail and provider"})
			}
		}
		// A lease signs in through SSO or a visit key only: any other credential is out of policy, however it got
		// there (made before the agent ran, by an administrator, by the person while self-service was on).
		for _, c := range ou.Credentials {
			add(Action{Kind: DeleteCredential, Username: name, UserID: ou.ID, Credential: c,
				Why: "no lease grants a credential of kind " + c.Kind})
		}
		for _, k := range ou.Keys {
			if norm, _ := normaliseKey(k.OpenSSH); norm == "" || !du.Keys[norm] {
				add(Action{Kind: DeleteKey, Username: name, UserID: ou.ID, KeyID: k.ID, Why: "no live visit lease installs it"})
			}
		}
	}
	for _, name := range sortedKeys(d.Users) {
		du := d.Users[name]
		if o.Unreadable[name] {
			continue
		}
		if o.Unmanaged[name] {
			p.Drift = append(p.Drift, fmt.Sprintf("user %s exists on the bastion and is not managed by ReliKey: "+
				"not touched; rename or remove it to let the lease apply", name))
			continue
		}
		ou := o.Managed[name]
		uid := ""
		if ou == nil {
			add(Action{Kind: CreateUser, Username: name, Why: "a live lease"})
		} else {
			uid = ou.ID
		}
		if du.Email != "" && (ou == nil || !slices.ContainsFunc(ou.SSO, func(c bastion.Identity) bool {
			return c.Email == du.Email && c.Provider == provider
		})) {
			add(Action{Kind: AddSSO, Username: name, UserID: uid, Email: du.Email, Why: "sign-in for a live lease"})
		}
		for _, key := range sortedKeys(du.Keys) {
			if ou == nil || !slices.ContainsFunc(ou.Keys, func(k bastion.Key) bool {
				norm, _ := normaliseKey(k.OpenSSH)
				return norm == key
			}) {
				add(Action{Kind: AddKey, Username: name, UserID: uid, Key: key, Why: "sign-in for a live visit lease"})
			}
		}
		for _, role := range sortedKeys(du.Roles) {
			rid, ok := o.Roles[role]
			if !ok {
				p.Drift = append(p.Drift, fmt.Sprintf("role %s is not configured on the bastion: lease for %s not applied "+
					"(the installation creates roles and binds them to targets)", role, name))
				continue
			}
			end := du.Roles[role].UTC().Truncate(time.Second)
			var have *bastion.Grant
			if ou != nil {
				if ra, ok := ou.Roles[role]; ok {
					have = &ra
				}
			}
			switch {
			case have == nil:
				add(Action{Kind: AddRole, Username: name, UserID: uid, Role: role, RoleID: rid, Expires: end, Why: "a live lease"})
			case !have.Active:
				// A bastion may keep a removed grant as inactive (a soft delete), and then only a
				// new grant makes it active again (Warpgate v0.30.0 does, lab).
				add(Action{Kind: AddRole, Username: name, UserID: uid, Role: role, RoleID: rid, Expires: end,
					Why: "a live lease (the assignment was removed before)"})
			case have.Expires == nil || absDur(have.Expires.Sub(end)) > expirySlack:
				add(Action{Kind: SetExpiry, Username: name, UserID: uid, Role: role, RoleID: rid, Expires: end,
					Why: "the lease's end"})
			}
		}
	}
	slices.SortStableFunc(p.Actions, func(a, b Action) int { return cmp.Compare(a.Kind, b.Kind) })
	return p
}

// Result is what an execution did.
type Result struct {
	Done    int
	Failed  []string
	Applied []Action // the actions that succeeded, in order (for the events, decision 0025)
}

// Execute runs the plan in order. When ctx is done (the shutdown signal) no grant
// starts, and removals keep running for at most grace (keep it below the container's
// stop timeout), then stop. A failure is recorded and the next action runs: every
// action is idempotent and the next tick plans again from what is observed.
func Execute(ctx context.Context, bas bastion.Admin, provider string, p Plan, grace time.Duration) Result {
	var r Result
	created := map[string]string{}
	removals, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	defer context.AfterFunc(ctx, func() { time.AfterFunc(grace, stop) })()
	closeFailed := map[string]bool{}
	for _, a := range p.Actions {
		if a.Kind == DeleteUser && closeFailed[a.Username] {
			// Deleting the user would hide its open session from every later tick.
			r.Failed = append(r.Failed, "kept until its sessions are closed: "+a.String())
			continue
		}
		if a.Kind.Grant() && ctx.Err() != nil {
			r.Failed = append(r.Failed, "stopped before grants: "+a.String())
			continue
		}
		if removals.Err() != nil {
			r.Failed = append(r.Failed, "stopped at the end of the shutdown grace: "+a.String())
			continue
		}
		actx, cancel := context.WithTimeout(removals, 20*time.Second)
		if a.UserID == "" {
			a.UserID = created[a.Username]
		}
		err := run(actx, bas, provider, a, created)
		cancel()
		if err != nil {
			if a.Kind == CloseSession {
				closeFailed[a.Username] = true
			}
			r.Failed = append(r.Failed, a.String()+": "+err.Error())
			continue
		}
		r.Done++
		r.Applied = append(r.Applied, a)
	}
	return r
}

func run(ctx context.Context, bas bastion.Admin, provider string, a Action, created map[string]string) error {
	if a.UserID == "" && a.Kind != CreateUser && a.Kind != CloseSession {
		return fmt.Errorf("user %s was not created", a.Username)
	}
	switch a.Kind {
	case CloseSession:
		return ignoreNotFound(bas.CloseSession(ctx, a.Session))
	case RemoveRole:
		return ignoreNotFound(bas.Revoke(ctx, a.UserID, a.RoleID))
	case DeleteSSO:
		return ignoreNotFound(bas.RemoveIdentity(ctx, a.UserID, a.SSOID))
	case DeleteCredential:
		return ignoreNotFound(bas.RemoveCredential(ctx, a.UserID, a.Credential))
	case DeleteUser:
		return ignoreNotFound(bas.DeleteAccount(ctx, a.UserID))
	case CreateUser:
		u, err := bas.CreateAccount(ctx, a.Username, Marker)
		if err != nil {
			return err
		}
		created[a.Username] = u.ID
		// A bastion may give a new account default roles without expiry (Warpgate does); only leases grant
		// roles here, so they go before anything else (AG-7).
		ras, err := bas.Grants(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, ra := range ras {
			if err := ignoreNotFound(bas.Revoke(ctx, u.ID, ra.RoleID)); err != nil {
				return err
			}
		}
		return nil
	case AddSSO:
		return bas.AddIdentity(ctx, a.UserID, provider, a.Email)
	case DeleteKey:
		return ignoreNotFound(bas.RemoveKey(ctx, a.UserID, a.KeyID))
	case AddKey:
		return bas.AddKey(ctx, a.UserID, "relikey visit lease", a.Key)
	case AddRole:
		return bas.Grant(ctx, a.UserID, a.RoleID, a.Expires)
	case SetExpiry:
		return bas.SetGrantExpiry(ctx, a.UserID, a.RoleID, a.Expires)
	}
	return fmt.Errorf("unknown action %v", a.Kind)
}

func ignoreNotFound(err error) error {
	if bastion.NotFound(err) {
		return nil // already gone: the removal converged
	}
	return err
}

// narrowVisits returns the desired state without the roles that only visit leases grant
// and that reach a target those leases do not name, or whose targets could not be read:
// a bastion role grants all its targets, so assigning it would over-grant (C-06). A
// role the bastion does not have stays, and is reported where roles are assigned. The
// input is not modified.
func narrowVisits(d Desired, o *Observed) (Desired, []string) {
	var drift []string
	out := d
	out.Users = map[string]*DesiredUser{}
	for name, du := range d.Users {
		cp := *du
		cp.Roles = map[string]time.Time{}
		for role, end := range du.Roles {
			_, visitOnly := du.VisitTargets[role]
			allowed := append(slices.Clone(du.LeaseTargets[role]), du.VisitTargets[role]...)
			kind := "lease"
			if visitOnly {
				kind = "visit lease"
			}
			if _, configured := o.Roles[role]; configured {
				reach, read := o.RoleTargets[role]
				if !read {
					drift = append(drift, fmt.Sprintf("the targets of role %s could not be read: the %s for %s not applied this tick",
						role, kind, name))
					continue
				}
				extra := slices.DeleteFunc(slices.Clone(reach), func(t string) bool { return slices.Contains(allowed, t) })
				if len(extra) > 0 {
					slices.Sort(extra)
					drift = append(drift, fmt.Sprintf("role %s reaches %s, which the %s for %s does not name: "+
						"not applied (bind the role to the lease's targets only)", role, strings.Join(extra, ", "), kind, name))
					continue
				}
			}
			cp.Roles[role] = end
		}
		out.Users[name] = &cp
	}
	slices.Sort(drift)
	return out, drift
}

// sessionCap is how long a session on a target may run: the most generous cap among the
// user's live roles that reach the target; 0 when any of them has no cap.
func sessionCap(du *DesiredUser, targetRoles []string) time.Duration {
	best, found := time.Duration(0), false
	for _, r := range targetRoles {
		if _, live := du.Roles[r]; !live {
			continue
		}
		c := du.MaxSession[r]
		if c == 0 {
			return 0
		}
		if !found || c > best {
			best, found = c, true
		}
	}
	return best
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Summary is a one-line description for logs.
func (p Plan) Summary() string {
	if len(p.Actions) == 0 {
		return "in step"
	}
	counts := map[string]int{}
	for _, a := range p.Actions {
		counts[a.Name]++
	}
	parts := []string{}
	for _, k := range sortedKeys(counts) {
		parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}

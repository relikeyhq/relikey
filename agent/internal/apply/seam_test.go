// SPDX-License-Identifier: EUPL-1.2

package apply

import (
	"context"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"relikey/agent/internal/bastion"
	"relikey/agent/internal/kcedge"
)

// memBastion is a second bastion, in memory and deliberately unlike Warpgate (decision 0023): it deletes grants for
// good (no soft delete), its ids are its own ("acct-ann", "role-plc-operator"), it gives new accounts no default roles,
// and it serves no HTTP. If the plan converges here too, the plan depends on the bastion role, not on Warpgate.
type memBastion struct {
	mu       sync.Mutex
	accounts map[string]bastion.Account
	grants   map[string]map[string]*time.Time // account id -> role id -> expires
	ids      map[string][]bastion.Identity
	keys     map[string][]bastion.Key
	creds    map[string][]bastion.Credential
	roles    map[string]string   // role id -> name
	reach    map[string][]string // role id -> target names
	sessions map[string]bastion.Session
	n        int
}

func newMem(roles map[string][]string) *memBastion {
	m := &memBastion{accounts: map[string]bastion.Account{}, grants: map[string]map[string]*time.Time{},
		ids: map[string][]bastion.Identity{}, keys: map[string][]bastion.Key{}, creds: map[string][]bastion.Credential{}, roles: map[string]string{},
		reach: map[string][]string{}, sessions: map[string]bastion.Session{}}
	for name, targets := range roles {
		m.roles["role-"+name] = name
		m.reach["role-"+name] = targets
	}
	return m
}

func (m *memBastion) next(p string) string { m.n++; return p + "-" + strings.Repeat("x", m.n) }

func gone(what string) error { return &notFound{what} }

type notFound struct{ what string }

func (e *notFound) Error() string { return e.what + " is gone" }
func (e *notFound) Unwrap() error { return bastion.ErrNotFound }

func (m *memBastion) Accounts(context.Context) ([]bastion.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []bastion.Account{}
	for _, a := range m.accounts {
		out = append(out, a)
	}
	return out, nil
}

func (m *memBastion) CreateAccount(_ context.Context, name, desc string) (bastion.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := bastion.Account{ID: "acct-" + name, Name: name, Description: desc}
	m.accounts[a.ID] = a
	return a, nil
}

func (m *memBastion) DeleteAccount(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accounts[id]; !ok {
		return gone("account " + id)
	}
	delete(m.accounts, id)
	delete(m.grants, id)
	delete(m.ids, id)
	delete(m.keys, id)
	return nil
}

func (m *memBastion) Roles(context.Context) ([]bastion.Role, error) {
	out := []bastion.Role{}
	for id, n := range m.roles {
		out = append(out, bastion.Role{ID: id, Name: n})
	}
	return out, nil
}

func (m *memBastion) RoleTargets(_ context.Context, roleID string) ([]bastion.Target, error) {
	out := []bastion.Target{}
	for _, t := range m.reach[roleID] {
		out = append(out, bastion.Target{ID: t, Name: t})
	}
	return out, nil
}

func (m *memBastion) TargetRoles(_ context.Context, target string) ([]bastion.Role, error) {
	out := []bastion.Role{}
	for id, ts := range m.reach {
		if slices.Contains(ts, target) {
			out = append(out, bastion.Role{ID: id, Name: m.roles[id]})
		}
	}
	return out, nil
}

func (m *memBastion) Grants(_ context.Context, acct string) ([]bastion.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []bastion.Grant{}
	for rid, exp := range m.grants[acct] {
		out = append(out, bastion.Grant{RoleID: rid, Role: m.roles[rid], Expires: exp, Active: true})
	}
	return out, nil
}

func (m *memBastion) Grant(_ context.Context, acct, rid string, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.grants[acct] == nil {
		m.grants[acct] = map[string]*time.Time{}
	}
	m.grants[acct][rid] = &exp
	return nil
}

func (m *memBastion) SetGrantExpiry(ctx context.Context, acct, rid string, exp time.Time) error {
	return m.Grant(ctx, acct, rid, exp)
}

func (m *memBastion) Revoke(_ context.Context, acct, rid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.grants[acct][rid]; !ok {
		return gone("grant " + rid)
	}
	delete(m.grants[acct], rid) // for good: no soft delete here
	return nil
}

func (m *memBastion) Identities(_ context.Context, acct string) ([]bastion.Identity, error) {
	return slices.Clone(m.ids[acct]), nil
}

func (m *memBastion) AddIdentity(_ context.Context, acct, provider, email string) error {
	m.ids[acct] = append(m.ids[acct], bastion.Identity{ID: m.next("id"), Provider: provider, Email: email})
	return nil
}

func (m *memBastion) RemoveIdentity(_ context.Context, acct, id string) error {
	m.ids[acct] = slices.DeleteFunc(m.ids[acct], func(i bastion.Identity) bool { return i.ID == id })
	return nil
}

func (m *memBastion) Keys(_ context.Context, acct string) ([]bastion.Key, error) {
	return slices.Clone(m.keys[acct]), nil
}

func (m *memBastion) AddKey(_ context.Context, acct, label, k string) error {
	m.keys[acct] = append(m.keys[acct], bastion.Key{ID: m.next("key"), Label: label, OpenSSH: k})
	return nil
}

func (m *memBastion) RemoveKey(_ context.Context, acct, id string) error {
	m.keys[acct] = slices.DeleteFunc(m.keys[acct], func(k bastion.Key) bool { return k.ID == id })
	return nil
}

func (m *memBastion) Credentials(_ context.Context, acct string) ([]bastion.Credential, error) {
	return slices.Clone(m.creds[acct]), nil
}

func (m *memBastion) RemoveCredential(_ context.Context, acct string, c bastion.Credential) error {
	m.creds[acct] = slices.DeleteFunc(m.creds[acct], func(x bastion.Credential) bool { return x == c })
	return nil
}

func (m *memBastion) ActiveSessions(context.Context) ([]bastion.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []bastion.Session{}
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out, nil
}

func (m *memBastion) CloseSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return gone("session " + id)
	}
	delete(m.sessions, id)
	return nil
}

func (m *memBastion) open(acct, target string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.next("sess")
	a := m.accounts["acct-"+acct]
	m.sessions[id] = bastion.Session{ID: id, Account: a.Name, AccountID: a.ID,
		Targets: []bastion.TargetSession{{TargetID: target, Started: t0}}}
	return id
}

func converge(t *testing.T, b bastion.Admin, leases []kcedge.Lease, visits []kcedge.VisitLease) {
	t.Helper()
	for i := 0; i < 3; i++ {
		d := FromLive(leases, visits)
		d.Now = t0
		o, err := Observe(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.ReadRoleTargets(context.Background(), b, d); err != nil {
			t.Fatal(err)
		}
		p := Compute(d, o, provider)
		if len(p.Actions) == 0 {
			return
		}
		if r := Execute(context.Background(), b, provider, p, time.Second); len(r.Failed) > 0 {
			t.Fatalf("failed on the second bastion: %v", r.Failed)
		}
	}
	t.Fatal("the plan did not converge on the second bastion within three ticks")
}

func TestThePlanDrivesASecondDifferentBastion(t *testing.T) {
	m := newMem(map[string][]string{"plc-operator": {"target-plc"}, "hmi-viewer": {"target-hmi"}})
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(4*time.Hour)), lease("L-2", "bob", "hmi-viewer", t0.Add(time.Hour))}
	converge(t, m, leases, nil)
	if exp := m.grants["acct-ann"]["role-plc-operator"]; exp == nil || !exp.Equal(t0.Add(4*time.Hour)) {
		t.Fatalf("ann's grant on the second bastion: %v", m.grants["acct-ann"])
	}
	if len(m.ids["acct-bob"]) != 1 || m.ids["acct-bob"][0].Email != "bob@example.test" {
		t.Fatalf("bob's sign-in identity: %v", m.ids["acct-bob"])
	}

	sid := m.open("ann", "target-plc")
	converge(t, m, leases[1:], nil) // ann's lease ended
	if _, open := m.sessions[sid]; open {
		t.Fatal("ann's session stayed open after her lease ended")
	}
	if _, still := m.accounts["acct-ann"]; still {
		t.Fatal("ann's account stayed after her lease ended")
	}
	if _, kept := m.accounts["acct-bob"]; !kept {
		t.Fatal("bob's account went with ann's lease")
	}
}

// The core packages name no product (decision 0023): only the composition root (cmd/relikey-agent) and the adapters
// may import the Warpgate package, and no core file imports the test fakes.
func TestTheCoreImportsNoProduct(t *testing.T) {
	for _, dir := range []string{".", filepath.Join("..", "agent")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			pf, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range pf.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if strings.HasSuffix(p, "/internal/warpgate") || strings.HasSuffix(p, "/internal/fakes") {
					t.Errorf("%s imports %s: the core speaks to the bastion role, not to a product", f, p)
				}
			}
		}
	}
}

// SPDX-License-Identifier: EUPL-1.2

package apply

import (
	"fmt"
	"relikey/agent/internal/bastion"
	"testing"
	"time"

	"relikey/agent/internal/kcedge"
)

// FuzzCompute builds random leases and a random Warpgate from the fuzzer's bytes and
// checks the planner's invariants: nothing is planned for an unmanaged user, every
// removal comes before every grant, the plan is deterministic, and no grant goes to a
// username two people share.
func FuzzCompute(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add([]byte{0, 0, 0, 0, 255, 255, 255, 255, 3, 3, 3, 3})
	names := []string{"ann", "bob", "cid", "dee", "breakglass"}
	roles := []string{"plc-operator", "hmi-viewer", "missing-role"}
	f.Fuzz(func(t *testing.T, b []byte) {
		at := 0
		next := func() int {
			if at >= len(b) {
				return 0
			}
			at++
			return int(b[at-1])
		}
		var leases []kcedge.Lease
		for i := range next() % 7 {
			n := names[next()%len(names)]
			l := kcedge.Lease{LeaseID: fmt.Sprintf("L-%d", i), Username: n, Person: "idp:" + n, Role: roles[next()%len(roles)],
				Email: n + "@example.test", Ends: t0.Add(time.Duration(next()) * time.Minute)}
			if next()%5 == 0 {
				l.Person = "idp:someone-else"
			}
			if next()%6 == 0 {
				l.Email = ""
			}
			leases = append(leases, l)
		}
		o := &Observed{Roles: map[string]string{"plc-operator": "r1", "hmi-viewer": "r2"}, Managed: map[string]*ObservedUser{},
			Unmanaged: map[string]bool{"breakglass": true}, TargetRoles: map[string][]string{"t1": {"plc-operator"},
				"t2": {"hmi-viewer"}}, Unreadable: map[string]bool{}}
		for i, n := range names[:4] {
			if next()%2 == 0 {
				continue
			}
			ou := &ObservedUser{ID: fmt.Sprintf("u%d", i), Roles: map[string]bastion.Grant{}}
			for _, r := range roles[:2] {
				if next()%2 == 1 {
					exp := t0.Add(time.Duration(next()) * time.Minute)
					ou.Roles[r] = bastion.Grant{RoleID: o.Roles[r], Role: r, Expires: &exp, Active: next()%4 != 0}
				}
			}
			if next()%2 == 1 {
				ou.SSO = []bastion.Identity{{ID: "c" + n, Provider: "keycloak", Email: n + "@example.test"}}
			}
			if next()%2 == 1 {
				ou.Sessions = []bastion.Session{{ID: "s" + n, Account: n, AccountID: ou.ID,
					Targets: []bastion.TargetSession{{TargetID: []string{"t1", "t2"}[next()%2], Started: t0}}}}
			}
			if next()%7 == 0 {
				o.Unreadable[n] = true
				continue
			}
			o.Managed[n] = ou
		}
		d := FromLeases(leases)
		d.Now = t0.Add(time.Duration(next()) * time.Minute)
		p, q := Compute(d, o, "keycloak"), Compute(d, o, "keycloak")
		if len(p.Actions) != len(q.Actions) {
			t.Fatal("not deterministic")
		}
		shared := map[string]map[string]bool{}
		for _, l := range leases {
			if shared[l.Username] == nil {
				shared[l.Username] = map[string]bool{}
			}
			shared[l.Username][l.Person] = true
		}
		granted := false
		for i, a := range p.Actions {
			if a.String() != q.Actions[i].String() {
				t.Fatal("not deterministic")
			}
			if a.Username == "breakglass" {
				t.Fatalf("an action on the unmanaged user: %v", a)
			}
			if o.Unreadable[a.Username] && (a.Kind.Grant() || d.Users[a.Username] != nil) {
				t.Fatalf("a grant, or an action under a live lease, on a user that could not be read: %v", a)
			}
			if a.Kind.Grant() {
				granted = true
				if len(shared[a.Username]) > 1 {
					t.Fatalf("a grant to a username two people share: %v", a)
				}
			} else if granted {
				t.Fatalf("a removal after a grant: %v", p.Actions)
			}
		}
	})
}

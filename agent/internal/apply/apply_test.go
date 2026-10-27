// SPDX-License-Identifier: EUPL-1.2

package apply

import (
	"context"
	"fmt"
	"math/rand/v2"
	"relikey/agent/internal/bastion"
	"slices"
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/warpgate"
)

const provider = "keycloak"

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*fakes.Warpgate, bastion.Admin) {
	t.Helper()
	fw := fakes.NewWarpgate("tok", map[string][]string{"plc-operator": {"target-plc"}, "hmi-viewer": {"target-hmi"}})
	fw.Now = func() time.Time { return t0 }
	srv, base, pin := fw.Serve()
	t.Cleanup(srv.Close)
	hc, err := httpx.New(httpx.Options{Timeout: 10 * time.Second, PinSHA256: pin})
	if err != nil {
		t.Fatal(err)
	}
	return fw, warpgate.Bastion{C: &warpgate.Client{Base: base, Token: "tok", HTTP: hc, RetryBase: time.Millisecond}}
}

// leaseTarget is the target each test role is bound to in setup: a lease names it (AG-11).
var leaseTarget = map[string]string{"plc-operator": "target-plc", "hmi-viewer": "target-hmi"}

func lease(id, user, role string, ends time.Time) kcedge.Lease {
	t := leaseTarget[role]
	if t == "" {
		t = "target-" + role
	}
	return kcedge.Lease{LeaseID: id, Username: user, Email: user + "@example.test", Role: role, Target: t, Ends: ends}
}

func reconcile(t *testing.T, wg bastion.Admin, leases []kcedge.Lease) Plan {
	t.Helper()
	o, err := observeAll(wg)
	if err != nil {
		t.Fatal(err)
	}
	p := Compute(FromLeases(leases), o, provider)
	if r := Execute(context.Background(), wg, provider, p, 5*time.Second); len(r.Failed) > 0 {
		t.Fatalf("failed: %v", r.Failed)
	}
	return p
}

func steady(t *testing.T, wg bastion.Admin, leases []kcedge.Lease) {
	t.Helper()
	o, err := observeAll(wg)
	if err != nil {
		t.Fatal(err)
	}
	if p := Compute(FromLeases(leases), o, provider); len(p.Actions) > 0 {
		t.Fatalf("not converged, still: %v", p.Actions)
	}
}

func TestLeasesBecomeUsersRolesAndSignInThenConverge(t *testing.T) {
	fw, wg := setup(t)
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(4*time.Hour)),
		lease("L-2", "ann", "hmi-viewer", t0.Add(2*time.Hour)), lease("L-3", "bob", "hmi-viewer", t0.Add(time.Hour))}
	reconcile(t, wg, leases)
	steady(t, wg, leases)
	view, emails := fw.Snapshot(Marker)
	if !view["ann"]["plc-operator"].Equal(t0.Add(4*time.Hour)) || !view["bob"]["hmi-viewer"].Equal(t0.Add(time.Hour)) {
		t.Fatalf("view %v", view)
	}
	if !slices.Equal(emails["ann"], []string{"ann@example.test"}) {
		t.Fatalf("emails %v", emails)
	}
}

func TestAnEndedLeaseClosesSessionsBeforeRemovingAccess(t *testing.T) {
	fw, wg := setup(t)
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))}
	reconcile(t, wg, leases)
	sid, err := fw.OpenSession("ann", "target-plc")
	if err != nil {
		t.Fatal(err)
	}
	p := reconcile(t, wg, nil)
	kinds := []Kind{}
	for _, a := range p.Actions {
		kinds = append(kinds, a.Kind)
	}
	if !slices.Equal(kinds, []Kind{CloseSession, RemoveRole, DeleteSSO, DeleteUser}) {
		t.Fatalf("plan %v", p.Actions)
	}
	if fw.SessionOpen(sid) {
		t.Fatal("the session outlived the lease")
	}
	if view, _ := fw.Snapshot(Marker); len(view) != 0 {
		t.Fatalf("users left: %v", view)
	}
	steady(t, wg, nil)
}

func TestLosingOneRoleClosesOnlyTheSessionsItReached(t *testing.T) {
	fw, wg := setup(t)
	both := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour)),
		lease("L-2", "ann", "hmi-viewer", t0.Add(time.Hour))}
	reconcile(t, wg, both)
	plc, _ := fw.OpenSession("ann", "target-plc")
	hmi, _ := fw.OpenSession("ann", "target-hmi")
	reconcile(t, wg, both[1:]) // plc-operator ends
	if fw.SessionOpen(plc) || !fw.SessionOpen(hmi) {
		t.Fatalf("plc open %v (want false), hmi open %v (want true)", fw.SessionOpen(plc), fw.SessionOpen(hmi))
	}
	steady(t, wg, both[1:])
}

func TestAnUnmanagedUserIsNeverTouched(t *testing.T) {
	fw, wg := setup(t)
	fw.AddUser("breakglass", "installer account")
	fw.AddUser("ann", "made by an operator")
	p := reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	if len(p.Actions) != 0 || !slices.ContainsFunc(p.Drift, func(s string) bool { return strings.Contains(s, "not managed") }) {
		t.Fatalf("plan %v drift %v", p.Actions, p.Drift)
	}
	if view, _ := fw.Snapshot(Marker); len(view) != 0 {
		t.Fatalf("managed users appeared: %v", view)
	}
}

// grantAs gives an account a role through the admin API, the way an operator would behind the agent's back.
func grantAs(t *testing.T, wg bastion.Admin, userID, role string, expires time.Time) {
	t.Helper()
	roles, err := wg.Roles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.Name == role {
			if err := wg.Grant(context.Background(), userID, r.ID, expires); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no role %s", role)
}

func TestAnUnmanagedAccountHoldingAGovernedRoleIsReportedNotTouched(t *testing.T) {
	fw, wg := setup(t)
	rogue := fw.AddUser("rogue", "made behind the agent's back")
	admin := fw.AddUser("admin", "the bastion's own admin")
	grantAs(t, wg, rogue, "plc-operator", t0.Add(24*time.Hour))
	grantAs(t, wg, admin, "hmi-viewer", t0.Add(24*time.Hour)) // a role no lease grants: not governed here
	o, err := observeAll(wg)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ReadUnmanagedGrants(context.Background(), wg, map[string]bool{"plc-operator": true}, t0); err != nil {
		t.Fatal(err)
	}
	p := Compute(FromLeases(nil), o, provider)
	joined := strings.Join(p.Drift, "\n")
	if !strings.Contains(joined, "account rogue is not managed by ReliKey but holds the governed role plc-operator") {
		t.Fatalf("not reported: %v", p.Drift)
	}
	if strings.Contains(joined, "account admin") {
		t.Fatalf("an ungoverned role was reported: %v", p.Drift)
	}
	if len(p.Actions) != 0 {
		t.Fatalf("an unmanaged account was acted on: %v", p.Actions)
	}
}

func TestAnExpiredGrantOnAnUnmanagedAccountIsNotReported(t *testing.T) {
	fw, wg := setup(t)
	fw.IgnoreExpiry = true // a bastion whose clock lags keeps the grant active: the agent's own clock decides
	grantAs(t, wg, fw.AddUser("old", "made by an operator"), "plc-operator", t0.Add(-time.Hour))
	o, _ := observeAll(wg)
	if err := o.ReadUnmanagedGrants(context.Background(), wg, map[string]bool{"plc-operator": true}, t0); err != nil {
		t.Fatal(err)
	}
	if len(o.Rogue["old"]) != 0 {
		t.Fatalf("an expired grant was reported: %v", o.Rogue)
	}
}

func TestTheGovernedRolesFileIsASCIMListOfGroups(t *testing.T) {
	g, err := ParseGoverned([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":1,
		"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"plc-operator"}]}`))
	if err != nil || !g["plc-operator"] || len(g) != 1 {
		t.Fatalf("%v %v", g, err)
	}
	empty, err := ParseGoverned([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"Resources":[]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("an empty list is a statement: %v %v", empty, err)
	}
	for _, bad := range []string{``, `{}`, `{"Resources":[]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"Resources":[{"displayName":"x"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":" "}]}`} {
		if _, err := ParseGoverned([]byte(bad)); err == nil {
			t.Fatalf("accepted %q: an unreadable file must never read as nothing governed", bad)
		}
	}
}

func TestDriftIsReportedNotGuessed(t *testing.T) {
	_, wg := setup(t)
	noMail := lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))
	noMail.Email = ""
	p := reconcile(t, wg, []kcedge.Lease{noMail, lease("L-2", "bob", "no-such-role", t0.Add(time.Hour))})
	joined := strings.Join(p.Drift, "\n")
	if !strings.Contains(joined, "carries no e-mail") || !strings.Contains(joined, "role no-such-role is not configured") {
		t.Fatalf("drift %v", p.Drift)
	}
	if slices.ContainsFunc(p.Actions, func(a Action) bool { return a.Kind == AddSSO && a.Username == "ann" }) {
		t.Fatal("an SSO credential was guessed")
	}
}

func TestAnExtendedLeaseMovesTheExpiry(t *testing.T) {
	fw, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	later := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(3*time.Hour))}
	p := reconcile(t, wg, later)
	if len(p.Actions) != 1 || p.Actions[0].Kind != SetExpiry {
		t.Fatalf("plan %v", p.Actions)
	}
	if view, _ := fw.Snapshot(Marker); !view["ann"]["plc-operator"].Equal(t0.Add(3 * time.Hour)) {
		t.Fatalf("view %v", view)
	}
}

func TestFaultsConvergeOverTicks(t *testing.T) {
	fw, wg := setup(t)
	fw.FailRate = 0.4
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour)),
		lease("L-2", "bob", "hmi-viewer", t0.Add(time.Hour)), lease("L-3", "cid", "hmi-viewer", t0.Add(time.Hour))}
	for range 60 {
		if o, err := observeAll(wg); err == nil {
			Execute(context.Background(), wg, provider, Compute(FromLeases(leases), o, provider), 5*time.Second)
		}
	}
	fw.FailRate = 0
	steady(t, wg, leases)
	if _, failed := fw.Counts(); failed == 0 {
		t.Fatal("no fault was injected")
	}
}

func TestNoGrantStartsAfterShutdown(t *testing.T) {
	_, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	o, _ := observeAll(wg)
	p := Compute(FromLeases([]kcedge.Lease{lease("L-2", "bob", "hmi-viewer", t0.Add(time.Hour))}), o, provider)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Execute(ctx, wg, provider, p, 5*time.Second)
	o2, _ := observeAll(wg)
	if o2.Managed["ann"] != nil {
		t.Fatal("the removal did not run after the signal")
	}
	if o2.Managed["bob"] != nil || len(r.Failed) == 0 {
		t.Fatalf("a grant ran after the signal (%v)", r.Failed)
	}
}

func TestComputeIsDeterministic(t *testing.T) {
	_, wg := setup(t)
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour)),
		lease("L-2", "bob", "hmi-viewer", t0.Add(time.Hour))}
	o, _ := observeAll(wg)
	a, b := Compute(FromLeases(leases), o, provider), Compute(FromLeases(leases), o, provider)
	if a.Summary() != b.Summary() || len(a.Actions) != len(b.Actions) {
		t.Fatal("two computations differ")
	}
	for i := range a.Actions {
		if a.Actions[i].String() != b.Actions[i].String() {
			t.Fatalf("action %d differs", i)
		}
	}
}

func TestASessionWhoseUserVanishedIsClosed(t *testing.T) {
	fw, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	sid, _ := fw.OpenSession("ann", "target-plc")
	users, _ := wg.Accounts(context.Background())
	for _, u := range users {
		_ = wg.DeleteAccount(context.Background(), u.ID) // deleted behind the agent's back
	}
	reconcile(t, wg, nil)
	if fw.SessionOpen(sid) {
		t.Fatal("an orphaned session stayed open")
	}
}

// Full-stack run 2: the agent closed an SSH session while it waited for the person's out-of-band approval
// (no user and no target yet), so a person with a live lease could never get in when a tick fell in that window.
func TestASessionStillSigningInIsLeftAlone(t *testing.T) {
	fw, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	sid := fw.OpenSigningIn()
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	if !fw.SessionOpen(sid) {
		t.Fatal("a session still signing in was closed")
	}
}

func TestAUserIsNotDeletedWhileItsSessionCouldNotBeClosed(t *testing.T) {
	fw, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	sid, _ := fw.OpenSession("ann", "target-plc")
	o, _ := observeAll(wg)
	p := Compute(FromLeases(nil), o, provider)
	fw.FailRate = 1                                      // every call fails from here: the close fails
	wg.(warpgate.Bastion).C.RetryBase = time.Microsecond // the Warpgate adapter's own retry pacing
	r := Execute(context.Background(), wg, provider, p, time.Second)
	fw.FailRate = 0
	if !slices.ContainsFunc(r.Failed, func(s string) bool { return strings.HasPrefix(s, "kept until its sessions are closed") }) {
		t.Fatalf("the delete was attempted: %v", r.Failed)
	}
	reconcile(t, wg, nil) // the next tick finishes the job
	if fw.SessionOpen(sid) {
		t.Fatal("the session stayed open")
	}
}

func TestASessionLongerThanItsLeasesAllowIsClosed(t *testing.T) {
	fw, wg := setup(t)
	short := lease("L-1", "ann", "plc-operator", t0.Add(8*time.Hour))
	short.MaxSessionHours = 1
	reconcile(t, wg, []kcedge.Lease{short})
	sid, _ := fw.OpenSession("ann", "target-plc") // started at t0 (the fake's clock)
	run := func(at time.Time, leases ...kcedge.Lease) {
		o, err := observeAll(wg)
		if err != nil {
			t.Fatal(err)
		}
		d := FromLeases(leases)
		d.Now = at
		Execute(context.Background(), wg, provider, Compute(d, o, provider), time.Second)
	}
	run(t0.Add(59*time.Minute), short)
	if !fw.SessionOpen(sid) {
		t.Fatal("closed before its hour")
	}
	generous := lease("L-2", "ann", "plc-operator", t0.Add(8*time.Hour))
	generous.MaxSessionHours = 4
	run(t0.Add(2*time.Hour), short, generous) // the most generous live lease decides
	if !fw.SessionOpen(sid) {
		t.Fatal("closed although another lease allows four hours")
	}
	run(t0.Add(61*time.Minute+3*time.Hour), short, generous)
	if fw.SessionOpen(sid) {
		t.Fatal("the session ran past every lease's cap")
	}
}

func TestNoCapMeansNoLimit(t *testing.T) {
	fw, wg := setup(t)
	l := lease("L-1", "ann", "plc-operator", t0.Add(48*time.Hour))
	reconcile(t, wg, []kcedge.Lease{l})
	sid, _ := fw.OpenSession("ann", "target-plc")
	o, _ := observeAll(wg)
	d := FromLeases([]kcedge.Lease{l})
	d.Now = t0.Add(30 * time.Hour)
	if p := Compute(d, o, provider); len(p.Actions) != 0 || !fw.SessionOpen(sid) {
		t.Fatalf("plan %v", p.Actions)
	}
}

// TestRandomLeaseSetsConverge drives random lease sets through reconcile, a fault-free
// step after each faulty one, and checks the invariants after every fault-free step:
// Warpgate holds exactly the desired roles, expiries and e-mails; the unmanaged user is
// untouched; a second plan is empty.
func TestRandomLeaseSetsConverge(t *testing.T) {
	fw, wg := setup(t)
	fw.AddUser("breakglass", "installer")
	rng := rand.New(rand.NewPCG(2026, 10))
	people := []string{"ann", "bob", "cid", "dee"}
	roles := []string{"plc-operator", "hmi-viewer", "no-such-role"}
	for step := range 200 {
		var leases []kcedge.Lease
		for i := range rng.IntN(6) {
			l := lease(fmt.Sprintf("L-%d-%d", step, i), people[rng.IntN(len(people))], roles[rng.IntN(len(roles))],
				t0.Add(time.Duration(1+rng.IntN(48))*time.Hour))
			if rng.IntN(10) == 0 {
				l.Email = ""
			}
			leases = append(leases, l)
		}
		if step%3 == 1 { // a faulty pass first: partial work must still converge
			fw.FailRate = 0.5
			if o, err := observeAll(wg); err == nil {
				Execute(context.Background(), wg, provider, Compute(FromLeases(leases), o, provider), time.Second)
			}
			fw.FailRate = 0
		}
		reconcile(t, wg, leases)
		steady(t, wg, leases)
		want := FromLeases(leases)
		view, emails := fw.Snapshot(Marker)
		for u, du := range want.Users {
			for r, end := range du.Roles {
				if r == "no-such-role" {
					continue
				}
				if got, ok := view[u][r]; !ok || !got.Equal(end.UTC().Truncate(time.Second)) {
					t.Fatalf("step %d: %s %s = %v, want %v", step, u, r, got, end)
				}
			}
			if du.Email != "" && !slices.Equal(emails[u], []string{du.Email}) {
				t.Fatalf("step %d: %s e-mails %v, want [%s]", step, u, emails[u], du.Email)
			}
		}
		for u, rs := range view {
			for r := range rs {
				if _, ok := want.Users[u].Roles[r]; want.Users[u] == nil || !ok {
					t.Fatalf("step %d: %s holds %s without a lease", step, u, r)
				}
			}
		}
		if !fw.UserExists("breakglass", "installer") {
			t.Fatalf("step %d: the unmanaged user was touched", step)
		}
	}
}

// A person who makes their own account unreadable (Warpgate self-service: keys with huge labels) is still closed and
// deleted when the lease ends: neither needs the per-user reads (stack attack 2026-10-25, E1).
func TestAnUnreadableAccountIsStillRemovedWhenItsLeaseEnds(t *testing.T) {
	fw, wg := setup(t)
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))}
	reconcile(t, wg, leases)
	sid, err := fw.OpenSession("ann", "target-plc")
	if err != nil {
		t.Fatal(err)
	}
	fw.Refuse = func(method, path string) bool { return strings.HasSuffix(path, "/credentials/public-keys") }
	if p := reconcile(t, wg, leases); len(p.Actions) != 0 { // a live lease: nothing is changed blind
		t.Fatalf("actions on an unreadable user under a live lease: %v", p.Actions)
	}
	p := reconcile(t, wg, nil)
	if fw.SessionOpen(sid) {
		t.Fatalf("the session outlived the lease: %v", p.Actions)
	}
	if view, _ := fw.Snapshot(Marker); len(view) != 0 {
		t.Fatalf("the unreadable user was kept: %v", view)
	}
}

// When closing a session fails, the user is kept (deleting it would hide the session) but loses its role and SSO at
// once, so it cannot sign in again meanwhile (stack attack 2026-10-25, E5).
func TestAFailedCloseStillTakesAwayRoleAndSSO(t *testing.T) {
	fw, wg := setup(t)
	leases := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))}
	reconcile(t, wg, leases)
	sid, err := fw.OpenSession("ann", "target-plc")
	if err != nil {
		t.Fatal(err)
	}
	fw.Refuse = func(method, path string) bool { return strings.HasSuffix(path, "/close") }
	o, err := observeAll(wg)
	if err != nil {
		t.Fatal(err)
	}
	if r := Execute(context.Background(), wg, provider, Compute(FromLeases(nil), o, provider), time.Second); len(r.Failed) != 2 {
		t.Fatalf("want the close and the delete to fail, got %v", r.Failed)
	}
	view, emails := fw.Snapshot(Marker)
	if _, kept := view["ann"]; !kept || len(emails["ann"]) != 0 {
		t.Fatalf("after a failed close: view %v, emails %v (want the user kept, no SSO)", view, emails)
	}
	if len(view["ann"]) != 0 {
		t.Fatalf("roles still active after a failed close: %v", view["ann"])
	}
	fw.Refuse = nil
	reconcile(t, wg, nil)
	if fw.SessionOpen(sid) {
		t.Fatal("the session was never closed")
	}
	steady(t, wg, nil)
}

// observeAll reads the bastion as the agent does each tick, with the targets of every role (ReadRoleTargets reads
// those of the roles a lease grants; AG-11 needs them).
func observeAll(wg bastion.Admin) (*Observed, error) {
	o, err := Observe(context.Background(), wg)
	if err != nil {
		return o, err
	}
	o.RoleTargets = map[string][]string{}
	for name, id := range o.Roles {
		ts, err := wg.RoleTargets(context.Background(), id)
		if err != nil {
			return o, err
		}
		names := []string{}
		for _, t := range ts {
			names = append(names, t.Name)
		}
		o.RoleTargets[name] = names
	}
	return o, nil
}

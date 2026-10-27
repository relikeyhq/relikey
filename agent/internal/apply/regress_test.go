// SPDX-License-Identifier: EUPL-1.2

package apply

import (
	"slices"
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/kcedge"
)

// AG-9: two people under one username get nothing, and it is reported.
func TestTwoPeopleOneUsernameFailClosed(t *testing.T) {
	_, wg := setup(t)
	a := lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))
	b := lease("L-2", "ann", "hmi-viewer", t0.Add(time.Hour))
	a.Person, b.Person, b.Email = "idp:ann", "idp:mallory", "mallory@example.test"
	p := reconcile(t, wg, []kcedge.Lease{a, b})
	if len(p.Actions) != 0 || !slices.ContainsFunc(p.Drift, func(s string) bool { return strings.Contains(s, "share the username") }) {
		t.Fatalf("plan %v drift %v", p.Actions, p.Drift)
	}
}

// AG-6: an assignment Warpgate already ended (soft delete, expiry) is not removed again.
func TestAnInactiveAssignmentIsNotRemovedAgain(t *testing.T) {
	fw, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	fw.Now = func() time.Time { return t0.Add(2 * time.Hour) } // expired in Warpgate's eyes
	o, _ := observeAll(wg)
	d := FromLeases([]kcedge.Lease{lease("L-2", "ann", "hmi-viewer", t0.Add(3*time.Hour))})
	for _, a := range Compute(d, o, provider).Actions {
		if a.Kind == RemoveRole {
			t.Fatalf("an inactive assignment was planned for removal: %v", a)
		}
	}
}

// AG-8: a session is matched to its user by id; one whose user id is unknown is an
// orphan, whatever its username says.
func TestSessionsAreMatchedByUserID(t *testing.T) {
	fw, wg := setup(t)
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	sid, _ := fw.OpenSession("ann", "target-plc")
	o, _ := observeAll(wg)
	if len(o.Managed["ann"].Sessions) != 1 || o.Managed["ann"].Sessions[0].ID != sid || len(o.Orphans) != 0 {
		t.Fatalf("sessions %v orphans %v", o.Managed["ann"].Sessions, o.Orphans)
	}
}

// AG-7: a user the agent creates keeps none of Warpgate's default roles.
func TestANewUserLosesDefaultRoles(t *testing.T) {
	fw, wg := setup(t)
	fw.DefaultRole("hmi-viewer")
	reconcile(t, wg, []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))})
	view, _ := fw.Snapshot(Marker)
	if _, ok := view["ann"]["hmi-viewer"]; ok || len(view["ann"]) != 1 {
		t.Fatalf("roles %v", view["ann"])
	}
}

// e2e (Warpgate v0.30.0): a removed assignment stays listed as inactive; a lease that wants
// the role again must reactivate it, which only a POST does.
func TestARemovedRoleIsGrantedAgainByPost(t *testing.T) {
	fw, wg := setup(t)
	l := lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))
	other := lease("L-2", "ann", "hmi-viewer", t0.Add(time.Hour))
	reconcile(t, wg, []kcedge.Lease{l, other})
	reconcile(t, wg, []kcedge.Lease{other}) // plc-operator removed: soft-deleted in Warpgate
	reconcile(t, wg, []kcedge.Lease{l, other})
	steady(t, wg, []kcedge.Lease{l, other})
	if view, _ := fw.Snapshot(Marker); view["ann"]["plc-operator"].IsZero() {
		t.Fatalf("the role was not granted again: %v", view["ann"])
	}
}

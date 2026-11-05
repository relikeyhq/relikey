// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"encoding/json/v2"
	"fmt"
	"testing"
	"time"

	"relikey/agent/internal/apply"
	"relikey/agent/internal/bastion"
	"relikey/agent/internal/fakes"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/internal/state"
)

var removalNow = time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC)

func holding(user string, roles ...string) *apply.ObservedUser {
	ou := &apply.ObservedUser{Roles: map[string]bastion.Grant{}}
	for _, r := range roles {
		ou.Roles[r] = bastion.Grant{Role: r, Active: true}
	}
	return ou
}

func TestARemovalIsConfirmedOnlyOnceTheRoleIsSeenGone(t *testing.T) {
	ann := state.Assignment{User: "ann", Role: "plc-operator"}
	l1 := kcedge.Lease{LeaseID: "L-1", Username: "ann", Role: "plc-operator"}
	for _, c := range []struct {
		name      string
		l         live
		o         *apply.Observed
		confirmed bool
	}{
		{"the role is gone", live{}, &apply.Observed{Managed: map[string]*apply.ObservedUser{"ann": holding("ann")}}, true},
		{"the account is gone", live{}, &apply.Observed{Managed: map[string]*apply.ObservedUser{}}, true},
		{"the role is still there", live{}, &apply.Observed{Managed: map[string]*apply.ObservedUser{"ann": holding("ann", "plc-operator")}}, false},
		{"the account was not read", live{}, &apply.Observed{Managed: map[string]*apply.ObservedUser{}, Unreadable: map[string]bool{"ann": true}}, false},
		{"the account lost its marker", live{}, &apply.Observed{Managed: map[string]*apply.ObservedUser{}, Unmanaged: map[string]bool{"ann": true}}, false},
		{"the lease is still live", live{leases: []kcedge.Lease{l1}}, &apply.Observed{Managed: map[string]*apply.ObservedUser{"ann": holding("ann")}}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := state.Record{Held: map[string]state.Assignment{"L-1": ann}}
			got, _ := confirmRemovals(rec, c.l, nil, c.o, removalNow, "warpgate")
			want := []kcedge.Removal(nil)
			if c.confirmed {
				want = []kcedge.Removal{{LeaseID: "L-1", System: "warpgate", At: "2026-11-05T09:30:00Z"}}
			}
			if fmt.Sprint(got.Removals) != fmt.Sprint(want) {
				t.Fatalf("removals %v, want %v", got.Removals, want)
			}
			if _, kept := got.Held["L-1"]; kept == c.confirmed {
				t.Fatalf("L-1 still remembered: %v, confirmed: %v", kept, c.confirmed)
			}
			if rec.Held["L-1"] != ann || rec.Removals != nil {
				t.Fatal("the store's record was changed in place")
			}
		})
	}
}

// A lease is remembered only once its role is seen held; one never applied is never confirmed as removed.
func TestOnlyAHeldLeaseIsRemembered(t *testing.T) {
	l := live{leases: []kcedge.Lease{{LeaseID: "L-1", Username: "ann", Role: "plc-operator"}},
		visits: []kcedge.VisitLease{{LeaseID: "V-1", Username: "bob", Role: "plc-visit"}}}
	o := &apply.Observed{Managed: map[string]*apply.ObservedUser{}}
	got, changed := confirmRemovals(state.Record{}, l, map[string]map[string]bool{"bob": {"plc-visit": true}}, o, removalNow, "warpgate")
	if !changed || len(got.Held) != 1 || got.Held["V-1"] != (state.Assignment{User: "bob", Role: "plc-visit"}) {
		t.Fatalf("held %v (changed %v), want only V-1", got.Held, changed)
	}
	if _, changed := confirmRemovals(got, l, map[string]map[string]bool{"bob": {"plc-visit": true}}, o, removalNow, "warpgate"); changed {
		t.Fatal("an unchanged tick changed the record (a write that only wears the flash)")
	}
}

func TestPendingRemovalsAreBounded(t *testing.T) {
	rec := state.Record{Held: map[string]state.Assignment{"L-new": {User: "ann", Role: "r"}}}
	for i := range maxPendingRemovals {
		rec.Removals = append(rec.Removals, kcedge.Removal{LeaseID: fmt.Sprintf("L-%d", i), System: "warpgate", At: "x"})
	}
	got, _ := confirmRemovals(rec, live{}, nil, &apply.Observed{Managed: map[string]*apply.ObservedUser{}}, removalNow, "warpgate")
	if len(got.Removals) != maxPendingRemovals || got.Removals[0].LeaseID != "L-1" || got.Removals[len(got.Removals)-1].LeaseID != "L-new" {
		t.Fatalf("%d removals, first %s, last %s", len(got.Removals), got.Removals[0].LeaseID, got.Removals[len(got.Removals)-1].LeaseID)
	}
}

// End to end: a lease ends, the agent removes the role, the next report confirms the removal, and once delivered the
// confirmation leaves the edge's state.
func TestAnEndedLeaseIsConfirmedInTheReport(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.eventually("the lease is remembered as held", func() bool { _, ok := r.store.Get().Held["L-1"]; return ok })
	r.kc.SetLeases(nil, nil)
	r.eventually("the removal is reported", func() bool {
		var rep keyclerk.Report
		return json.Unmarshal(r.kc.LastReport(), &rep) == nil && len(rep.Removals) == 1 &&
			rep.Removals[0].LeaseID == "L-1" && rep.Removals[0].System == "warpgate"
	})
	r.eventually("the delivered removal leaves the state", func() bool {
		rec := r.store.Get()
		return len(rec.Removals) == 0 && len(rec.Held) == 0
	})
	if _, ok := r.roles("ann")["plc-operator"]; ok {
		t.Fatal("ann still holds the role")
	}
}

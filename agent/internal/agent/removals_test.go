// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"path/filepath"
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

// A role taken away behind the agent while its lease runs is a lease_ended_early incident for that lease (edge protocol
// 1.4), sent once and dropped from the state when delivered; the drift line stays.
func TestARoleRemovedOutsideIsALeaseEndedEarlyIncident(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.eventually("a tick that sees it", func() bool { return r.status().PlanActions == 0 })
	r.wg.RevokeRole("ann", "plc-operator")
	r.eventually("the incident is taken", func() bool {
		in, _ := r.kc.TakenIncidents()
		return len(in) >= 1 && in[0]["kind"] == "lease_ended_early" && in[0]["lease_id"] == "L-1" &&
			in[0]["system"] == "warpgate" && in[0]["at"] != ""
	})
	r.eventually("and leaves the state", func() bool { return len(r.store.Get().EndedEarly) == 0 })
	if in, refused := r.kc.TakenIncidents(); len(in) != 1 || refused != 0 {
		t.Fatalf("%d incidents taken, %d refused: want one, none", len(in), refused)
	}
}

// An incident the desk refuses (the lease left the last bundle) is dropped, never sent again. It is planted in the
// store before the agent runs: the agent is the store's only writer.
func TestARefusedIncidentIsNotSentAgain(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) {
		rec := a.Store.Get()
		rec.EndedEarly = []kcedge.EndedEarly{{LeaseID: "L-gone", System: "warpgate", At: "2026-11-05T09:30:00Z"}}
		if err := a.Store.Save(rec); err != nil {
			t.Fatal(err)
		}
	})
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("refused and dropped", func() bool {
		_, refused := r.kc.TakenIncidents()
		return refused == 1 && len(r.store.Get().EndedEarly) == 0
	})
	p0 := pulls(r.kc)
	r.eventually("three more pulls, each with a report", func() bool { return pulls(r.kc) >= p0+3 })
	if _, refused := r.kc.TakenIncidents(); refused != 1 {
		t.Fatalf("refused %d times: sent again", refused)
	}
}

// The report declares what the bastion enforces (edge protocol 1.4), from the version Warpgate shows the agent.
func TestTheReportDeclaresTheBastion(t *testing.T) {
	r := newRig(t, Enforce)
	r.eventually("the declaration is reported", func() bool {
		var rep keyclerk.Report
		if json.Unmarshal(r.kc.LastReport(), &rep) != nil || rep.Bastion == nil {
			return false
		}
		b := rep.Bastion
		return b.Product == "warpgate" && b.Version == "0.30.2" &&
			fmt.Sprint(b.Capabilities) == "[ends_sessions_on_revoke expires_grants injects_credentials]" &&
			fmt.Sprint(b.Adapter) == "[reads_hardening]"
	})
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

// decision 0028: a node promoted by hand reports how it became active (edge protocol 1.5 section 7.3), read from its
// activation file at each report, so the promotion reaches the desk without a restart.
func TestAPromotedNodeReportsItsActivation(t *testing.T) {
	file := filepath.Join(t.TempDir(), ActivationName)
	r := newRigTuned(t, func(a *Agent) { a.ActivationFile = file })
	r.eventually("a report without an activation", func() bool {
		var rep keyclerk.Report
		return json.Unmarshal(r.kc.LastReport(), &rep) == nil && rep.AppliedSerial > 0 && rep.Activation == nil
	})
	stmt := jsontext.Value(`{"bytes":"e30=","signatures":[]}`)
	if err := WriteActivation(file, keyclerk.Activation{By: "break_glass", At: "2026-11-06T15:00:00Z", Statement: stmt}); err != nil {
		t.Fatal(err)
	}
	r.eventually("the activation is reported, the statement whole", func() bool {
		var rep keyclerk.Report
		return json.Unmarshal(r.kc.LastReport(), &rep) == nil && rep.Activation != nil &&
			rep.Activation.By == "break_glass" && rep.Activation.At == "2026-11-06T15:00:00Z" &&
			string(rep.Activation.Statement) == string(stmt)
	})
}

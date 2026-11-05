// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"relikey/agent/internal/apply"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/internal/state"
)

// maxPendingRemovals bounds the confirmations kept while the desk cannot be reached: about 100 bytes each. Beyond it
// the oldest go: the desk then lacks those leaver proofs, while the removals themselves still happened.
const maxPendingRemovals = 5000

// confirmRemovals is the leaver proof (edge protocol 1.4, section 7.1). A lease whose role the bastion was seen holding
// is remembered by its id; once the lease is no longer live and the account, read this tick, no longer holds the role
// (the agent removed it, the bastion expired it, or the account is gone), the removal is confirmed at the trusted time
// now. A role another live lease still grants stays, so that lease's removal waits until it goes too. The record is
// copied, never changed in place: the store hands out its own maps.
func confirmRemovals(rec state.Record, l live, held map[string]map[string]bool, o *apply.Observed, now time.Time,
	system string) (state.Record, bool) {
	heldNow := map[string]state.Assignment{}
	for _, x := range l.leases {
		if held[x.Username][x.Role] {
			heldNow[x.LeaseID] = state.Assignment{User: x.Username, Role: x.Role}
		}
	}
	for _, x := range l.visits {
		if held[x.Username][x.Role] {
			heldNow[x.LeaseID] = state.Assignment{User: x.Username, Role: x.Role}
		}
	}
	liveIDs := map[string]bool{}
	for _, x := range l.leases {
		liveIDs[x.LeaseID] = true
	}
	for _, x := range l.visits {
		liveIDs[x.LeaseID] = true
	}
	next := map[string]state.Assignment{}
	removals := slices.Clone(rec.Removals)
	for id, as := range rec.Held {
		if liveIDs[id] {
			next[id] = as
			continue
		}
		if o == nil || o.Unreadable[as.User] {
			next[id] = as // not read this tick: confirmed later
			continue
		}
		if o.Unmanaged[as.User] {
			next[id] = as // no longer marked as ReliKey's: what it holds is not the agent's to vouch for
			continue
		}
		if ou := o.Managed[as.User]; ou != nil && ou.Roles[as.Role].Active {
			next[id] = as // still there: the plan removes it, or another live lease grants it
			continue
		}
		removals = append(removals, kcedge.Removal{LeaseID: id, System: system, At: formatWall(now)})
	}
	maps.Copy(next, heldNow)
	if len(removals) > maxPendingRemovals {
		removals = removals[len(removals)-maxPendingRemovals:]
	}
	changed := len(removals) != len(rec.Removals) || !maps.Equal(next, rec.Held)
	if !changed {
		return rec, false
	}
	if len(next) == 0 {
		next = nil
	}
	rec.Held, rec.Removals = next, removals
	return rec, true
}

// maxPendingEndedEarly bounds the lease_ended_early incidents kept while the desk cannot be reached; beyond it the
// oldest go (each is in the drift too).
const maxPendingEndedEarly = 500

// queueEndedEarly adds a lease_ended_early incident for each lease, at the trusted time now. The slice is copied: the
// store hands out its own.
func queueEndedEarly(pending []kcedge.EndedEarly, leaseIDs []string, system string, now time.Time) []kcedge.EndedEarly {
	out := slices.Clone(pending)
	for _, id := range leaseIDs {
		out = append(out, kcedge.EndedEarly{LeaseID: id, System: system, At: formatWall(now)})
	}
	if len(out) > maxPendingEndedEarly {
		out = out[len(out)-maxPendingEndedEarly:]
	}
	return out
}

// sendEndedEarly posts the pending lease_ended_early incidents in order. One delivered, or refused by the desk (4xx:
// the lease left the last bundle, or ended on time), leaves the record; a failed send stops and waits for the next
// report.
func (a *Agent) sendEndedEarly(ctx context.Context, pending []kcedge.EndedEarly) {
	done := 0
	for _, e := range pending {
		err := a.Clerk.SendIncident(ctx, keyclerk.Incident{Kind: "lease_ended_early", System: e.System, At: e.At,
			LeaseID: e.LeaseID, Detail: "the bastion removed the lease's role before the lease ends, not the agent"})
		var se *keyclerk.StatusError
		if err != nil && !(errors.As(err, &se) && se.Status >= 400 && se.Status < 500) {
			if !errors.Is(err, context.Canceled) {
				a.Log.Warn("lease_ended_early incident not delivered; sent again after the next pull", "lease", e.LeaseID, "err", err)
			}
			break
		}
		if err != nil {
			a.Log.Warn("the desk refused a lease_ended_early incident; not sent again", "lease", e.LeaseID, "err", err)
		}
		done++
	}
	if done == 0 {
		return
	}
	cur := a.Store.Get()
	if len(cur.EndedEarly) >= done && slices.Equal(cur.EndedEarly[:done], pending[:done]) {
		cur.EndedEarly = slices.Clone(cur.EndedEarly[done:])
		if err := a.Store.Save(cur); err != nil {
			a.Log.Error("cannot record the delivered incidents", "err", err)
		}
	}
}

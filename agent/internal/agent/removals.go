// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"maps"
	"slices"
	"time"

	"relikey/agent/internal/apply"
	"relikey/agent/internal/kcedge"
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

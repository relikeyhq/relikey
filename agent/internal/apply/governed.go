// SPDX-License-Identifier: EUPL-1.2

package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"relikey/agent/internal/bastion"
)

// SCIM's list and group schemas (RFC 7643, RFC 7644): the governed-roles file is a SCIM list of groups, so any
// governance source that speaks SCIM can write it.
const (
	scimList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

// ParseGoverned reads the bastion roles a governance source governs on this edge (full-stack run 2, finding 8): a SCIM
// ListResponse of Group resources, each role by its displayName. The edge's own targets file is one source
// (deploy/edge/targets.py writes it) and stays one, since no clerk can be assumed present; a catalogue a clerk signs
// is preferred once one is published. An empty list is a statement that nothing is governed, so a file that cannot be
// read or parsed is an error, never an empty set.
func ParseGoverned(b []byte) (map[string]bool, error) {
	var l struct {
		Schemas   []string `json:"schemas"`
		Resources []struct {
			Schemas     []string `json:"schemas"`
			DisplayName string   `json:"displayName"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("governed roles: %w", err)
	}
	if !slices.Contains(l.Schemas, scimList) {
		return nil, fmt.Errorf("governed roles: not a SCIM list (schemas must name %s)", scimList)
	}
	g := map[string]bool{}
	for i, r := range l.Resources {
		if !slices.Contains(r.Schemas, scimGroup) || strings.TrimSpace(r.DisplayName) == "" {
			return nil, fmt.Errorf("governed roles: resource %d is not a SCIM group with a displayName", i)
		}
		g[r.DisplayName] = true
	}
	return g, nil
}

// ReadUnmanagedGrants reads the grants of the accounts the agent does not manage and keeps, for each, the governed
// roles it holds now: an active grant not yet expired at now (zero now: expiry unchecked). Only a lease grants a
// governed role, so such an account was given one behind the agent's back (finding 8). Nothing is ever planned for
// it: Compute reports it and leaves it alone, because an unmanaged account may be the bastion's own admin or a
// site's break-glass account. An account whose grants cannot be read is reported as unchecked.
func (o *Observed) ReadUnmanagedGrants(ctx context.Context, bas bastion.Admin, governed map[string]bool, now time.Time) error {
	o.Rogue, o.RogueUnchecked = map[string][]string{}, map[string]bool{}
	for _, name := range sortedKeys(o.unmanagedIDs) {
		gs, err := bas.Grants(ctx, o.unmanagedIDs[name])
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			o.RogueUnchecked[name] = true
			o.Notes = append(o.Notes, fmt.Sprintf("account %s is not managed by ReliKey and its roles could not be read "+
				"this tick: not checked for governed roles", name))
			continue
		}
		for _, g := range gs {
			if g.Active && governed[g.Role] && (now.IsZero() || g.Expires == nil || g.Expires.After(now)) {
				o.Rogue[name] = append(o.Rogue[name], g.Role)
			}
		}
		slices.Sort(o.Rogue[name])
		o.Rogue[name] = slices.Compact(o.Rogue[name])
	}
	return nil
}

// SPDX-License-Identifier: EUPL-1.2

package kcedge

import "slices"

// CeilingDecision is keyclerk/policy/ceiling.rego (KeyClerk v0.21.2) in Go, rule for
// rule, until the signed policy module runs in process (wazero, decision 0007). It is
// tested against KeyClerk's ceiling policy vectors (tests/conformance/edge.json).
// Refusals come back sorted, as the policy's set is.
func CeilingDecision(ceiling Object, e CeilingEntry) (allow bool, refusals []string) {
	strsOf := func(k string) []string {
		var out []string
		l, _ := ceiling[k].([]Value)
		for _, v := range l {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	persons, roles, targets, classes := strsOf("persons"), strsOf("roles"), strsOf("targets"), strsOf("classes")
	maxLease, _ := asInt(ceiling["max_lease_hours"])
	maxOffline, _ := asInt(ceiling["max_offline_hours"])
	profile, _ := ceiling["profile"].(string)

	inside := slices.Contains(persons, e.Person)
	if !inside && e.Kind == "lease" && e.Class == "low" {
		inside = slices.ContainsFunc(e.Roles, func(r string) bool { return slices.Contains(roles, r) })
	}
	add := func(s string) {
		if !slices.Contains(refusals, s) {
			refusals = append(refusals, s)
		}
	}
	if !inside {
		add("the person is outside the edge's ceiling")
	}
	for _, t := range e.Targets {
		if !slices.Contains(targets, t) {
			add("a target outside the edge's ceiling")
		}
	}
	if e.Kind == "lease" && !slices.Contains(classes, e.Class) {
		add("a lease class the ceiling does not allow")
	}
	if e.Kind == "lease" && e.Hours > maxLease {
		add("longer than the ceiling's longest lease")
	}
	if e.Kind == "visit" && e.Hours > maxOffline {
		add("a visit window longer than the ceiling's longest offline validity")
	}
	if e.Kind == "visit" && (profile != "assured" || e.AttestedProfile != "assured") {
		add("visit leases need an assured edge, by its ceiling and its attestation")
	}
	slices.Sort(refusals)
	if refusals == nil {
		refusals = []string{}
	}
	return len(refusals) == 0, refusals
}

// CeilingPolicyGo adapts CeilingDecision to the verifier's hook.
func CeilingPolicyGo(ceiling Object, e CeilingEntry) (bool, error) {
	allow, _ := CeilingDecision(ceiling, e)
	return allow, nil
}

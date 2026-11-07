// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"strings"
	"testing"
)

// A ceiling without persons is noted, saying whom it still lets in; one with persons is not (walk 2026-11-06, F20:
// the ceiling admitted nobody and the edge got no leases without a word).
func TestACeilingWithoutPersonsIsNoted(t *testing.T) {
	list := func(s ...string) []Value {
		out := []Value{}
		for _, x := range s {
			out = append(out, x)
		}
		return out
	}
	for name, c := range map[string]struct {
		ceiling Object
		want    string
	}{
		"the walk's: no persons, elevated only": {Object{"persons": list(), "roles": list("plc-operators"),
			"classes": list("elevated")}, "admits nobody"},
		"no persons, no roles": {Object{"persons": list(), "roles": list(), "classes": list("low")}, "admits nobody"},
		"no persons, low by role": {Object{"persons": list(), "roles": list("plc-operators"),
			"classes": list("low", "elevated")}, "only low-class leases by its roles"},
		"persons named": {Object{"persons": list("op:5c29"), "roles": list(), "classes": list("elevated")}, ""},
		"no ceiling":    {nil, ""},
	} {
		notes := CeilingNotes(c.ceiling)
		if c.want == "" {
			if len(notes) != 0 {
				t.Fatalf("%s: noted %v", name, notes)
			}
			continue
		}
		if len(notes) != 1 || !strings.Contains(notes[0], c.want) || !strings.Contains(notes[0], "anchors") {
			t.Fatalf("%s: %v, want one note with %q and what to do", name, notes, c.want)
		}
	}
}

// A ceiling whose longest lease is under a day is noted: memberships are granted in days, and the desk drops their
// leases until the last max_lease_hours (rc.3 walk R5, #166: the default 8 hours dropped a one-day membership's lease
// and nothing on the edge said so).
func TestACeilingShorterThanADayIsNoted(t *testing.T) {
	dave := []Value{"op:5c29"}
	for name, c := range map[string]struct {
		ceiling Object
		want    []string
	}{
		"the walk's: 8 hours": {Object{"persons": dave, "max_lease_hours": Number("8")}, []string{"at most 8 hours"}},
		"a day":               {Object{"persons": dave, "max_lease_hours": Number("24")}, nil},
		"a week":              {Object{"persons": dave, "max_lease_hours": Number("168")}, nil},
		"23 hours":            {Object{"persons": dave, "max_lease_hours": Number("23")}, []string{"at most 23 hours"}},
		"no persons, 8 hours": {Object{"persons": []Value{}, "roles": []Value{}, "max_lease_hours": Number("8")}, []string{"admits nobody", "at most 8 hours"}},
		"no max_lease_hours":  {Object{"persons": dave}, nil},
	} {
		notes := CeilingNotes(c.ceiling)
		if len(notes) != len(c.want) {
			t.Fatalf("%s: %v, want %d note(s)", name, notes, len(c.want))
		}
		for i, w := range c.want {
			if !strings.Contains(notes[i], w) || (strings.Contains(w, "hours") && !strings.Contains(notes[i], "at least 24")) {
				t.Fatalf("%s: note %q, want %q and what to do", name, notes[i], w)
			}
		}
	}
}

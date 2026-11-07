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

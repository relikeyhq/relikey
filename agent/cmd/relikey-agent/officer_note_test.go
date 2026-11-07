// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"strings"
	"testing"
)

// A statement that names its officer by username gets a note saying the desk will refuse it and what to ask for; an
// anchor gets none (walk 2026-11-06, F17: --officer carol, refused as "officer differ").
func TestAnOfficerNamedByUsernameIsNoted(t *testing.T) {
	for _, ok := range []string{"op:5c29853b-444f-4bb7-8693-3bac891bbe70", "idp:alice@example", "ext:vendor-1"} {
		if n := officerNote(ok); n != "" {
			t.Fatalf("%s: noted %q", ok, n)
		}
	}
	for _, bad := range []any{"carol", "Carol Example", "", nil, "op:"} {
		n := officerNote(bad)
		if !strings.Contains(n, "not an anchor") || !strings.Contains(n, "officer differ") || !strings.Contains(n, "--officer <their anchor>") {
			t.Fatalf("%v: %q", bad, n)
		}
	}
}

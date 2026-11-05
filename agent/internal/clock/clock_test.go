// SPDX-License-Identifier: EUPL-1.2

package clock

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func TestTrustedFollowsTheWallWhenBothAgree(t *testing.T) {
	c := &Fake{Wall: t0, Up: time.Hour}
	verifiedWall, verifiedBoot := c.Now(), c.Boot()
	c.Advance(10 * time.Minute)
	now, skewed := Trusted(c, verifiedWall, verifiedBoot, 5*time.Minute)
	if !now.Equal(t0.Add(10*time.Minute)) || skewed {
		t.Fatalf("now %v skewed %v", now, skewed)
	}
}

func TestAWallClockSetBackDoesNotStopTime(t *testing.T) {
	c := &Fake{Wall: t0, Up: time.Hour}
	verifiedWall, verifiedBoot := c.Now(), c.Boot()
	c.Advance(3 * time.Hour)
	c.Wall = t0.Add(-time.Hour) // someone sets the clock back
	now, skewed := Trusted(c, verifiedWall, verifiedBoot, 5*time.Minute)
	if !now.Equal(t0.Add(3*time.Hour)) || !skewed {
		t.Fatalf("now %v skewed %v, want the boot clock's %v", now, skewed, t0.Add(3*time.Hour))
	}
}

func TestAWallClockAheadIsUsedAndReported(t *testing.T) {
	c := &Fake{Wall: t0, Up: time.Hour}
	verifiedWall, verifiedBoot := c.Now(), c.Boot()
	c.Advance(time.Minute)
	c.Wall = c.Wall.Add(2 * time.Hour) // ahead: leases end earlier, which is the safe side
	now, skewed := Trusted(c, verifiedWall, verifiedBoot, 5*time.Minute)
	if !now.Equal(t0.Add(2*time.Hour+time.Minute)) || !skewed {
		t.Fatalf("now %v skewed %v", now, skewed)
	}
}

func TestWithoutAVerifyPointOnlyTheWallIsKnown(t *testing.T) {
	c := &Fake{Wall: t0, Up: time.Minute}
	if now, skewed := Trusted(c, time.Time{}, -1, 5*time.Minute); !now.Equal(t0) || skewed {
		t.Fatalf("now %v skewed %v", now, skewed)
	}
}

func TestSystemClockReadsBoth(t *testing.T) {
	var s System
	if s.Now().IsZero() || s.Boot() < 0 {
		t.Fatal("system clock unreadable")
	}
}

// A time namespace's offsets as /proc/self/timens_offsets prints them; what cannot be read is never "no offset".
func TestNamespaceOffsets(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"monotonic           0         0\nboottime            0         0\n", ""},
		{"monotonic           0         0\nboottime        -3600         0\n", "boottime by -1h0m0s"},
		{"monotonic          60         5\nboottime            0         0\n", "monotonic by 1m0.000000005s"},
	} {
		got, err := NamespaceOffsets(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"boottime x 0\n", "boottime 0\n"} {
		if _, err := NamespaceOffsets(bad); err == nil {
			t.Errorf("%q: read as no offset", bad)
		}
	}
}

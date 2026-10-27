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

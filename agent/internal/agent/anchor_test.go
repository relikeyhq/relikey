// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/clock"
	"relikey/agent/internal/fakes"
	"relikey/agent/internal/state"
)

// The attack the ratchet closes (edge protocol 1.5, relikeyhq/relikey#125), with one clock tampered at a time: the boot
// clock frozen for a day while the wall clock stays right (a paused virtual machine), thawed, then the wall clock set
// back a day. Without the ratchet the trusted time trails truth time by a day and a lease ends a day late.
func TestTheAnchorRatchetsThroughAFrozenBootClock(t *testing.T) {
	st, err := state.Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	t0 := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	clk := &clock.Fake{Wall: t0, Up: 1000 * time.Second, ID: "boot-1"}
	rec := st.Get()
	rec.BootID, rec.BootAtVerify, rec.WallAtVerify = "boot-1", int64(clk.Up), formatWall(t0)
	if err := st.Save(rec); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Clock: clk, Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	truth := t0
	tick := func() time.Time { now, _ := a.trustedNow(st.Get()); return now }

	for range 2 { // honest hours
		clk.Advance(time.Hour)
		truth = truth.Add(time.Hour)
		tick()
	}
	for range 24 { // the boot clock frozen, the wall clock right
		clk.Wall = clk.Wall.Add(time.Hour)
		truth = truth.Add(time.Hour)
		tick()
	}
	clk.Advance(time.Hour) // thawed
	truth = truth.Add(time.Hour)
	tick()
	clk.Wall = clk.Wall.Add(-24 * time.Hour) // the wall clock set back a day
	if got := tick(); got.Before(truth.Add(-time.Second)) {
		t.Fatalf("trusted %s trails real time %s by %s", got.Format(time.RFC3339), truth.Format(time.RFC3339), truth.Sub(got))
	}
	// the anchor was stored on the way (an hour or more past the stored one), so a restart within the boot keeps it
	if stored := parseWall(st.Get().WallAtVerify); stored.Before(truth.Add(-2 * time.Hour)) {
		t.Fatalf("the stored anchor %s is more than an hour behind %s", stored.Format(time.RFC3339), truth.Format(time.RFC3339))
	}
	a2 := &Agent{Clock: clk, Store: st, Log: a.Log} // a restart within the boot
	if got, _ := a2.trustedNow(st.Get()); got.Before(truth.Add(-time.Hour - time.Second)) {
		t.Fatalf("after a restart the trusted time %s trails %s by more than the hour between stores", got, truth)
	}
}

// bootClock is the real clock with a fixed boot id, as on Linux: the agent then has no anchor in this boot until a
// bundle verifies after the desk's time.
type bootClock struct {
	clock.System
	id string
}

func (b bootClock) BootID() string { return b.id }

// After a reboot, or before the first bundle, the desk's time comes first (edge protocol 1.5): the lease goes live only
// after it, and a desk that does not answer it (before 1.5) leaves nothing live.
func TestNoLeaseIsLiveBeforeTheDesksTime(t *testing.T) {
	t.Run("the desk answers", func(t *testing.T) {
		r := newRigTuned(t, func(a *Agent) { a.Clock = bootClock{id: "boot-A"} })
		r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
		r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
		if r.kc.TimeAsked() < 1 {
			t.Fatal("the lease went live without the desk's time")
		}
		if got := r.store.Get().BootID; got != "boot-A" {
			t.Fatalf("anchored in boot %q, want boot-A", got)
		}
	})
	t.Run("the desk has no time", func(t *testing.T) {
		r := newRigOff(t, Enforce, func(a *Agent) { a.Clock = bootClock{id: "boot-A"} })
		r.kc.SetNoTime(true)
		r.start()
		t.Cleanup(r.halt)
		r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
		r.eventually("asked for the time and refused the bundle", func() bool {
			return r.kc.TimeAsked() >= 2 && strings.Contains(r.status().LastRefusal, "desk's time")
		})
		if _, ok := r.roles("ann")["plc-operator"]; ok {
			t.Fatal("a lease went live without the desk's time")
		}
		// the bundle's reductions were stored at once (its floors), though nothing is live (edge protocol 1.5)
		if got := r.store.Get().Floors.Serial; got != r.kc.Serial() {
			t.Fatalf("stored floor serial %d, want the bundle's %d", got, r.kc.Serial())
		}
		// the desk's time returns: the stored bundle goes live without waiting for a new serial
		r.kc.SetNoTime(false)
		r.eventually("ann gets the role once the time verifies", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	})
}

// A week of clock faults, hour by hour, against the agent's own time path (trustedNow over clock.Ratchet and
// clock.Trusted, stored anchors and restarts within the boot), one clock tampered at a time. The invariant: the trusted
// time never trails real time by more than the skew, so no lease outlives its end by more than that. A forward glitch
// may hold the time ahead (leases end early): the accepted cost (relikeyhq/relikey#125).
func TestAWeekOfClockFaults(t *testing.T) {
	st, err := state.Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	t0 := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	clk := &clock.Fake{Wall: t0, Up: 1000 * time.Second, ID: "boot-1"}
	rec := st.Get()
	rec.BootID, rec.BootAtVerify, rec.WallAtVerify = "boot-1", int64(clk.Up), formatWall(t0)
	if err := st.Save(rec); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := &Agent{Clock: clk, Store: st, Log: log}
	truth, frozen, offset := t0, false, time.Duration(0) // offset: how far the wall clock is set from real time
	for hour := 1; hour <= 7*24; hour++ {
		truth = truth.Add(time.Hour)
		if !frozen {
			clk.Up += time.Hour
		}
		switch h := hour % 24; {
		case hour == 30: // a paused VM: the boot clock stops for a day, the wall clock stays right
			frozen = true
		case hour == 54: // thawed
			frozen = false
		case hour == 56: // then the wall clock set back a day (one clock at a time: the boot clock runs again)
			offset = -24 * time.Hour
		case hour == 60: // the wall clock put right again
			offset = 0
		case hour >= 80 && hour < 100: // set back four minutes before every tick: inside the skew, never accumulating
			offset = -4 * time.Minute
		case hour == 100:
			offset = 0
		case h == 12: // an agent restart within the boot: only the stored anchor survives
			a = &Agent{Clock: clk, Store: st, Log: log}
		case hour == 130: // a forward glitch of an hour, then corrected: the time may stay ahead (leases end early)
			offset = time.Hour
		case hour == 131:
			offset = 0
		}
		clk.Wall = truth.Add(offset)
		got, _ := a.trustedNow(st.Get())
		if lag := truth.Sub(got); lag > 5*time.Minute {
			t.Fatalf("hour %d: trusted %s trails real time %s by %s", hour, got.Format(time.RFC3339),
				truth.Format(time.RFC3339), lag)
		}
	}
}

// aheadClock is the real clock with the wall set forward and a fixed boot id.
type aheadClock struct {
	clock.System
	ahead time.Duration
}

func (c aheadClock) Now() time.Time { return time.Now().Add(c.ahead) }
func (c aheadClock) BootID() string { return "boot-A" }

// A wall clock set forward six hours must not open a lease that starts in two (edge protocol 1.5; six, not a day,
// keeps the bundle inside the ceiling's 12 offline hours, so only the start decides): the ratchet takes
// the forward wall as its anchor (leases end early), but starts are judged on the start anchor, verified time carried
// by the boot clock, so the lease stays shut however many ticks pass.
func TestAWallSetForwardDoesNotOpenALaterStart(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) { a.Clock = aheadClock{ahead: 6 * time.Hour} })
	start := time.Now().Add(2 * time.Hour)
	r.kc.SetLeases([]fakes.FakeLease{{ID: "L-1", Person: "idp:ann", Username: "ann", Email: "ann@example.test",
		Target: "plc", Role: "plc-operator", Class: "low", From: start, Until: start.Add(28 * time.Hour)}}, nil)
	r.eventually("the bundle is applied", func() bool { return r.status().AppliedSerial == r.kc.Serial() })
	t0 := r.status().Ticks
	r.eventually("more ticks with the wall six hours ahead", func() bool { return r.status().Ticks >= t0+20 })
	if _, ok := r.roles("ann")["plc-operator"]; ok {
		t.Fatal("a lease that starts in two hours opened on a wall clock set forward six hours")
	}
}

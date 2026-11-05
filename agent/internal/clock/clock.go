// SPDX-License-Identifier: EUPL-1.2

// Package clock gives the agent its two time sources behind one interface, so tests
// control both: the wall clock and the boot clock. The boot clock counts suspend
// (CLOCK_BOOTTIME on Linux), unlike Go's monotonic clock, and restarts at boot; the
// boot id tells boots apart (docs/go-engineering.md, Time).
package clock

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Clock is the agent's only source of time.
type Clock interface {
	Now() time.Time      // wall clock, UTC, no monotonic reading
	Boot() time.Duration // time since boot, counting suspend
	BootID() string      // changes at every boot; empty when unknown
}

// System is the real clock.
type System struct{}

func (System) Now() time.Time { return time.Now().UTC().Round(0) }

// Fake is a clock tests move by hand.
type Fake struct {
	Wall time.Time
	Up   time.Duration
	ID   string
}

func (f *Fake) Now() time.Time      { return f.Wall }
func (f *Fake) Boot() time.Duration { return f.Up }
func (f *Fake) BootID() string      { return f.ID }

// Advance moves both clocks, as real time passing does.
func (f *Fake) Advance(d time.Duration) { f.Wall, f.Up = f.Wall.Add(d), f.Up+d }

// Trusted is the moment the agent acts on: the wall clock, unless the boot clock since
// the last verified bundle says more time has passed, in which case the later moment
// wins (leases end earlier) and skewed reports it. A wall clock set back cannot keep a
// lease alive (decision 0007 point 4, GE-6). Without a verify point in this boot
// (bootAtVerify < 0) only the wall clock is known.
func Trusted(c Clock, wallAtVerify time.Time, bootAtVerify time.Duration, skew time.Duration) (now time.Time, skewed bool) {
	wall := c.Now()
	if bootAtVerify < 0 || wallAtVerify.IsZero() {
		return wall, false
	}
	byBoot := wallAtVerify.Add(c.Boot() - bootAtVerify)
	if byBoot.After(wall.Add(skew)) {
		return byBoot, true
	}
	return wall, wall.After(byBoot.Add(skew))
}

// NamespaceOffsets reads a time namespace's offsets, as /proc/self/timens_offsets prints them (Linux 5.6+): one line
// per clock, "<clock> <seconds> <nanoseconds>". It returns the clocks that are offset, "" when none is; content it
// cannot read is an error, never "no offset". An offset boottime clock makes the boot clock the agent bounds elapsed
// time with lie (KeyClerk decision 0032, second red team M3b).
func NamespaceOffsets(content string) (string, error) {
	var offset []string
	for line := range strings.Lines(content) {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return "", fmt.Errorf("timens_offsets line %q: want <clock> <seconds> <nanoseconds>", strings.TrimSpace(line))
		}
		secs, err1 := strconv.ParseInt(f[1], 10, 64)
		nanos, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			return "", fmt.Errorf("timens_offsets line %q: the offset is not a number", strings.TrimSpace(line))
		}
		if secs != 0 || nanos != 0 {
			offset = append(offset, fmt.Sprintf("%s by %s", f[0], time.Duration(secs)*time.Second+time.Duration(nanos)))
		}
	}
	return strings.Join(offset, ", "), nil
}

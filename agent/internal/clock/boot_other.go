// SPDX-License-Identifier: EUPL-1.2

//go:build !linux

package clock

import "time"

var start = time.Now()

// Boot outside Linux is time since the process started (development builds only; it
// does not count suspend).
func (System) Boot() time.Duration { return time.Since(start) }

// BootID outside Linux is unknown.
func (System) BootID() string { return "" }

// SPDX-License-Identifier: EUPL-1.2

package clock

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Boot reads CLOCK_BOOTTIME: it counts time in suspend. Inside a container it can be
// namespaced (Linux 5.6+ time namespaces); the footprint checks note it.
func (System) Boot() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return -1
	}
	return time.Duration(ts.Nano())
}

// BootID is the kernel's random id for this boot.
func (System) BootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

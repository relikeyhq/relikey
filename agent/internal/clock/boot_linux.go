// SPDX-License-Identifier: EUPL-1.2

package clock

import (
	"errors"
	"io/fs"
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

// TimeNamespaceOffset names the clocks this process's time namespace offsets ("" when none, or on a kernel without
// time namespaces).
func TimeNamespaceOffset() (string, error) {
	b, err := os.ReadFile("/proc/self/timens_offsets")
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return NamespaceOffsets(string(b))
}

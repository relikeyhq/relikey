// SPDX-License-Identifier: EUPL-1.2

package state

import (
	"fmt"
	"syscall"
)

const (
	tmpfsMagic   = 0x01021994
	overlayMagic = 0x794c7630
	ramfsMagic   = 0x858458f6
)

// checkDurable refuses file systems that do not survive a restart or sit on a
// container's writable layer.
func checkDurable(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("state directory %s: %w", dir, err)
	}
	switch int64(st.Type) {
	case tmpfsMagic, ramfsMagic:
		return fmt.Errorf("state directory %s is in memory (tmpfs): the floors would be lost at the next restart; "+
			"mount a persistent volume there", dir)
	case overlayMagic:
		return fmt.Errorf("state directory %s is on the container's overlay layer: mount a volume there", dir)
	}
	return nil
}

// SPDX-License-Identifier: EUPL-1.2

package state

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockDir takes an exclusive, non-blocking lock on the state directory's lock file.
func lockDir(root *os.Root) (func(), error) {
	f, err := root.OpenFile("lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another agent holds this state directory")
		}
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

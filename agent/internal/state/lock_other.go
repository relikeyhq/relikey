// SPDX-License-Identifier: EUPL-1.2

//go:build !linux

package state

import "os"

// lockDir outside Linux only keeps a lock file open (development builds).
func lockDir(root *os.Root) (func(), error) {
	f, err := root.OpenFile("lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
}

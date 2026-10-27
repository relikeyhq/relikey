// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"io/fs"

	"golang.org/x/sys/unix"
)

// harden: no core dumps and no same-user ptrace or /proc/<pid>/mem (secrets in memory
// cannot be zeroed reliably in Go; docs/go-engineering.md, Secrets in the process).
func harden() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func secretTooOpen(m fs.FileMode) bool { return m.Perm()&0o077 != 0 }

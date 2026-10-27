// SPDX-License-Identifier: EUPL-1.2

//go:build !linux

package main

import "io/fs"

// harden has nothing to do outside Linux (development builds only).
func harden() {}

// secretTooOpen cannot be judged from Unix mode bits outside Linux.
func secretTooOpen(fs.FileMode) bool { return false }

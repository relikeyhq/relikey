// SPDX-License-Identifier: EUPL-1.2

//go:build !linux

package state

// checkDurable has nothing to check outside Linux (development builds only).
func checkDurable(string) error { return nil }

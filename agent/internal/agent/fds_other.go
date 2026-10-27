// SPDX-License-Identifier: EUPL-1.2

//go:build !linux

package agent

func openFDs() int { return -1 }

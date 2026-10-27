// SPDX-License-Identifier: EUPL-1.2

package agent

import "os"

func openFDs() int {
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(es)
}

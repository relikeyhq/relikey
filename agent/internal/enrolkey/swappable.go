// SPDX-License-Identifier: EUPL-1.2

package enrolkey

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// A rotation ends with one rename of the staged key over the enrolment key, in the enrolment key's directory. That
// needs the directory writable by the agent and the key file not a mount of its own: a rename onto a single-file
// bind mount fails. The edge pod once mounted the key read-only as a single file (#134), so a rotation reached the
// desk and then could not finish on the edge. swappable says so at start instead.

// mountPoint reports whether path is a mount point of its own; a variable so tests can stand in for the kernel.
var mountPoint = func(path string) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // not Linux (development builds): nothing to read, nothing to refuse
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	return mountedAt(f, path)
}

// mountedAt reads /proc/self/mountinfo (proc(5)): the fifth field is the mount point, with space, tab, newline and
// backslash written as octal escapes.
func mountedAt(r io.Reader, file string) (bool, error) {
	want := path.Clean(filepath.ToSlash(file)) // the table is Linux's: slash-separated
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 5 {
			continue
		}
		if unescapeMount(f[4]) == want {
			return true, nil
		}
	}
	return false, s.Err()
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// swappable is nil when a rotation can finish: the agent can create a file in the enrolment key's directory and the
// key is not mounted as a file of its own. Otherwise it says what to change.
func swappable(current string) error {
	dir := filepath.Dir(current)
	probe, err := os.CreateTemp(dir, ".relikey-swap-probe-*")
	if err != nil {
		return fmt.Errorf("the agent cannot write the directory of enrolment_key_file (%s): %w. A rotation renames the "+
			"staged key over the enrolment key there, so it could not finish. Keep the keys in a directory the agent "+
			"can write (the edge pod: deploy/secrets/keys at /etc/relikey/keys; an older install moves its key with "+
			"python deploy/edge/install.py move-keys)", dir, err)
	}
	name := probe.Name()
	probe.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("%s: the agent's probe file cannot be removed (%w): remove it by hand", name, err)
	}
	own, err := mountPoint(current)
	if err != nil {
		return fmt.Errorf("cannot read the mount table to check enrolment_key_file %s: %w", current, err)
	}
	if own {
		return fmt.Errorf("enrolment_key_file %s is mounted as a file of its own, so nothing can be renamed over it "+
			"and a rotation could not finish. Mount its directory instead (the edge pod: deploy/secrets/keys at "+
			"/etc/relikey/keys; an older install moves its key with python deploy/edge/install.py move-keys)", current)
	}
	return nil
}

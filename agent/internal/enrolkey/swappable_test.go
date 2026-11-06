// SPDX-License-Identifier: EUPL-1.2

package enrolkey

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// The mount table as Linux writes it: the fifth field, with octal escapes for spaces.
func TestTheMountTableNamesMountPoints(t *testing.T) {
	table := strings.Join([]string{
		"22 1 0:21 / / rw,relatime - overlay overlay rw",
		"35 22 8:1 /srv/edge/deploy/secrets/enrolment.key /etc/relikey/enrolment.key ro,relatime - ext4 /dev/sda1 rw",
		`36 22 8:1 /srv/edge/my\040keys /etc/relikey/my\040keys rw,relatime - ext4 /dev/sda1 rw`,
	}, "\n")
	for path, want := range map[string]bool{
		"/etc/relikey/enrolment.key":      true,
		"/etc/relikey/my keys":            true,
		"/etc/relikey/keys/enrolment.key": false,
		"/etc/relikey":                    false,
	} {
		got, err := mountedAt(strings.NewReader(table), path)
		if err != nil || got != want {
			t.Errorf("%s: got %v %v, want %v", path, got, err, want)
		}
	}
}

func standIn(t *testing.T, mounted string) {
	t.Helper()
	was := mountPoint
	mountPoint = func(path string) (bool, error) { return path == mounted, nil }
	t.Cleanup(func() { mountPoint = was })
}

// #134: the pod mounted the key as a file of its own; a staged rotation is refused at start with the fix, and without
// one the agent runs on with a warning.
func TestAKeyMountedAsAFileOfItsOwnCannotBeRotated(t *testing.T) {
	g := newRig(t)
	standIn(t, g.curF)
	_, err := Load(g.opts())
	if err == nil || !strings.Contains(err.Error(), "mounted as a file of its own") ||
		!strings.Contains(err.Error(), "install.py move-keys") {
		t.Fatalf("got %v, want a refusal naming the mount and move-keys", err)
	}
	o := g.opts()
	o.Next, o.Statement = "", ""
	if _, err := Load(o); err != nil {
		t.Fatalf("nothing staged: the agent runs on, got %v", err)
	}
	if !strings.Contains(g.log.String(), "a rotation could not finish") {
		t.Fatalf("nothing staged: want a warning, log %q", g.log.String())
	}
}

// A key directory the agent cannot write: the same, with the directory named.
func TestAKeyInADirectoryTheAgentCannotWriteCannotBeRotated(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind here (Windows, or root)")
	}
	g := newRig(t)
	if err := os.Chmod(g.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(g.dir, 0o700) })
	_, err := Load(g.opts())
	if err == nil || !strings.Contains(err.Error(), "cannot write the directory of enrolment_key_file") ||
		!strings.Contains(err.Error(), "deploy/secrets/keys") {
		t.Fatalf("got %v, want a refusal naming the directory and the pod's key directory", err)
	}
}

// The probe leaves nothing behind in the key directory.
func TestTheProbeLeavesNothing(t *testing.T) {
	g := newRig(t)
	g.load(t)
	entries, _ := os.ReadDir(g.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "probe") {
			t.Fatalf("left %s", e.Name())
		}
	}
}

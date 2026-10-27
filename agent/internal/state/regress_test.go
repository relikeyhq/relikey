// SPDX-License-Identifier: EUPL-1.2

package state

import (
	"runtime"
	"strings"
	"testing"

	"relikey/agent/internal/kcedge"
)

// AG-5: a bundle as large as the KeyClerk client accepts survives a restart, and a
// record a restart could not read is never written.
func TestALargeBundleSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, true)
	big := &kcedge.Sealed{Bytes: strings.Repeat("A", 22<<20)} // 16 MiB as base64
	if err := s.Save(Record{Floors: kcedge.State{Serial: 2}, Bundle: big}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Record{Floors: kcedge.State{Serial: 3}, Bundle: &kcedge.Sealed{Bytes: strings.Repeat("A", 49<<20)}}); err == nil {
		t.Fatal("a record no restart can read was written")
	}
	s.Close()
	s2, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.Get().Floors.Serial; got != 2 {
		t.Fatalf("serial %d after restart, want 2", got)
	}
}

// AG-12: a second agent cannot open a state directory in use.
func TestOneAgentPerStateDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the lock is flock(2): Linux only")
	}
	dir := t.TempDir()
	a, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if b, err := Open(dir, true); err == nil {
		b.Close()
		t.Fatal("a second store opened the same directory")
	}
}

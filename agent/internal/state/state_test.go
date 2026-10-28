// SPDX-License-Identifier: EUPL-1.2

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"relikey/agent/internal/kcedge"
	"relikey/agent/pkg/events"
)

func rec(serial, ceiling int64, newest string) Record {
	return Record{Floors: kcedge.State{Serial: serial, CeilingSerial: ceiling, Newest: newest}, AppliedSerial: serial}
}

func TestFreshThenSaveAndReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get().Floors.Serial != 0 {
		t.Fatal("a fresh state must be zero")
	}
	for i := int64(1); i <= 5; i++ {
		if err := s.Save(rec(i, 2, "2026-10-23T12:00:00Z")); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s2, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.Get().Floors.Serial; got != 5 {
		t.Fatalf("serial %d after reopen, want 5", got)
	}
}

func TestFloorsOnlyRise(t *testing.T) {
	s, _ := Open(t.TempDir(), true)
	defer s.Close()
	if err := s.Save(rec(7, 3, "2026-10-23T12:00:00Z")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{rec(6, 3, "2026-10-23T12:00:00Z"), rec(7, 2, "2026-10-23T12:00:00Z"),
		rec(7, 3, "2026-10-23T11:59:59Z")} {
		if err := s.Save(r); !errors.Is(err, ErrFloorDown) {
			t.Fatalf("lowering %+v: %v", r.Floors, err)
		}
	}
	if s.Get().Floors.Serial != 7 {
		t.Fatal("a refused write changed the state")
	}
}

func TestATornSlotFallsBackToTheOther(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, true)
	_ = s.Save(rec(1, 1, "2026-10-23T12:00:00Z")) // slot A, gen 1
	_ = s.Save(rec(2, 1, "2026-10-23T12:00:00Z")) // slot B, gen 2
	s.Close()
	// Corrupt the newest slot (B): one flipped byte.
	p := filepath.Join(dir, "state-b.json")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0x01
	_ = os.WriteFile(p, b, 0o600)
	s2, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Get().Floors.Serial; got != 1 {
		t.Fatalf("serial %d, want the older valid slot (1)", got)
	}
	// The next write must go to the slot that is not the valid one (B) and win.
	if err := s2.Save(rec(3, 1, "2026-10-23T12:00:00Z")); err != nil {
		t.Fatal(err)
	}
	s2.Close()
	s3, _ := Open(dir, true)
	defer s3.Close()
	if got := s3.Get().Floors.Serial; got != 3 {
		t.Fatalf("serial %d, want 3", got)
	}
}

func TestBothSlotsUnreadableFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, true)
	_ = s.Save(rec(1, 1, ""))
	_ = s.Save(rec(2, 1, ""))
	s.Close()
	for _, n := range slots {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600)
	}
	if _, err := Open(dir, true); err == nil {
		t.Fatal("unreadable state must refuse to start")
	}
}

func TestATempFileLeftByACrashIsIgnored(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, true)
	_ = s.Save(rec(4, 1, ""))
	s.Close()
	_ = os.WriteFile(filepath.Join(dir, "state-b.json.tmp"), []byte("garbage"), 0o600)
	s2, err := Open(dir, true)
	if err != nil || s2.Get().Floors.Serial != 4 {
		t.Fatalf("serial %d, err %v", s2.Get().Floors.Serial, err)
	}
	s2.Close()
}

func head(epoch, seq int64) events.Head {
	return events.Head{Epoch: epoch, Seq: seq, Hash: fmt.Sprintf("%064x", seq)}
}

// The event chain's head survives a restart, only rises, and falls back to the other slot when the newest is torn.
func TestTheEventChainHeadSurvivesARestartAndOnlyRises(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, true)
	if s.Chain() != (events.Head{}) {
		t.Fatal("a fresh chain head must be zero")
	}
	for i := int64(1); i <= 3; i++ {
		if err := s.SaveChain(head(1, i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []events.Head{head(1, 3), head(1, 2), head(0, 4)} {
		if err := s.SaveChain(h); !errors.Is(err, ErrChainDown) {
			t.Fatalf("saving %+v over %+v: %v", h, s.Chain(), err)
		}
	}
	s.Close()
	s2, err := Open(dir, true)
	if err != nil || s2.Chain() != head(1, 3) {
		t.Fatalf("head %+v after reopen, err %v", s2.Chain(), err)
	}
	if s2.Get().Floors.Serial != 0 {
		t.Fatal("a chain head changed the floors")
	}
	s2.Close()
	// Slot A holds sequence 3 (generations 1 and 3), slot B sequence 2: tear A, B is read.
	p := filepath.Join(dir, "chain-a.json")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0x01
	_ = os.WriteFile(p, b, 0o600)
	s3, err := Open(dir, true)
	if err != nil || s3.Chain() != head(1, 2) {
		t.Fatalf("head %+v with the newest slot torn, err %v", s3.Chain(), err)
	}
	s3.Close()
	for _, n := range chainSlots {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600)
	}
	if _, err := Open(dir, true); err == nil {
		t.Fatal("an unreadable chain head must refuse to start: the sequence would reuse numbers")
	}
}

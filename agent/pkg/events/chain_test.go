// SPDX-License-Identifier: EUPL-1.2

package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// store is a chain head kept in memory, as the state directory keeps it.
type store struct {
	head  Head
	fail  bool
	saves int
}

func (s *store) save(h Head) error {
	if s.fail {
		return errors.New("disk full")
	}
	s.head, s.saves = h, s.saves+1
	return nil
}

// run emits n events on a chain continuing from the stored head and returns the lines written.
func run(t *testing.T, s *store, n int) ([][]byte, *Chain) {
	t.Helper()
	var buf bytes.Buffer
	c := NewChain(&buf, s.head, s.save)
	for i := range n {
		ev, err := New("edge-a", "relikey.account.created.v1", fmt.Sprintf("account:edge-a/u%d", i), Success, Info,
			"applied", at, map[string]any{"class_uid": 3001, "metadata": map[string]any{"version": "1.6.0"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Emit(ev); err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.SplitAfter(buf.Bytes(), []byte("\n"))
	return lines[:len(lines)-1], c
}

func hashOf(line []byte) string {
	sum := sha256.Sum256(bytes.TrimSuffix(line, []byte("\n")))
	return hex.EncodeToString(sum[:])
}

func TestEachLineCarriesItsSequenceAndTheHashOfTheLineBefore(t *testing.T) {
	s := &store{}
	lines, c := run(t, s, 3)
	prev := ""
	for i, line := range lines {
		var m struct {
			ID   string `json:"id"`
			Data struct {
				Metadata map[string]any `json:"metadata"`
				Unmapped map[string]any `json:"unmapped"`
			} `json:"data"`
		}
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		chain := m.Data.Unmapped["chain"].(map[string]any)
		if m.Data.Metadata["sequence"] != float64(i+1) || m.Data.Metadata["uid"] != m.ID ||
			m.Data.Metadata["version"] != "1.6.0" || chain["epoch"] != float64(1) || chain["prev"] != prev {
			t.Fatalf("line %d: metadata %v, chain %v (want prev %q)", i+1, m.Data.Metadata, chain, prev)
		}
		prev = hashOf(line)
	}
	want := Head{Epoch: 1, Seq: 3, Hash: prev}
	if c.Head() != want || s.head != want || s.saves != 3 {
		t.Fatalf("head %+v, stored %+v after %d saves, want %+v", c.Head(), s.head, s.saves, want)
	}
	if head, restarts, err := Verify(lines, &Head{}); err != nil || head != want || !slices.Equal(restarts, []int64{1}) {
		t.Fatalf("verify: %+v %v %v", head, restarts, err)
	}
}

func TestTheCallersEventIsNotChanged(t *testing.T) {
	meta := map[string]any{"version": "1.6.0"}
	ev, _ := New("edge-a", "relikey.account.created.v1", "account:edge-a/ann", Success, Info, "", at,
		map[string]any{"metadata": meta})
	if err := NewChain(&bytes.Buffer{}, Head{}, (&store{}).save).Emit(ev); err != nil {
		t.Fatal(err)
	}
	if len(meta) != 1 || ev.Data["unmapped"] != nil {
		t.Fatalf("the caller's event was changed: %v, %v", meta, ev.Data)
	}
}

func TestARemovedReorderedOrAlteredRecordBreaksTheChain(t *testing.T) {
	lines, c := run(t, &store{}, 4)
	alter := func(i int, old, new string) [][]byte {
		out := slices.Clone(lines)
		out[i] = bytes.Replace(out[i], []byte(old), []byte(new), 1)
		if bytes.Equal(out[i], lines[i]) {
			t.Fatalf("line %d holds no %s", i+1, old)
		}
		return out
	}
	broken := map[string][][]byte{
		"removed":                      slices.Delete(slices.Clone(lines), 1, 2),
		"reordered":                    {lines[0], lines[2], lines[1], lines[3]},
		"altered":                      alter(1, "u1", "u9"),
		"removed, the next renumbered": {lines[0], alter(2, `"sequence":3`, `"sequence":2`)[2]},
		"the first removed":            lines[1:],
	}
	for name, ls := range broken {
		if _, _, err := Verify(ls, &Head{}); !errors.Is(err, ErrBroken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The last record altered: the lines still chain, but not to the head reported later.
	head, _, err := Verify(alter(3, "u3", "u9"), &Head{})
	if err != nil || head == c.Head() {
		t.Fatalf("an altered last record: head %+v, reported %+v, %v", head, c.Head(), err)
	}
	// A verifier holding a head checks the rest of the stream against it.
	held := Head{Epoch: 1, Seq: 2, Hash: hashOf(lines[1])}
	if got, _, err := Verify(lines[2:], &held); err != nil || got != c.Head() {
		t.Fatalf("from a held head: %+v %v", got, err)
	}
	if _, _, err := Verify(lines[3:], &held); !errors.Is(err, ErrBroken) {
		t.Fatalf("a record after the held head removed: %v", err)
	}
}

func TestARestartOpensANewEpochAndTheSequenceGoesOn(t *testing.T) {
	s := &store{}
	first, _ := run(t, s, 2)
	second, c := run(t, s, 2)
	head, restarts, err := Verify(append(slices.Clone(first), second...), &Head{})
	if err != nil || head != c.Head() || head.Epoch != 2 || head.Seq != 4 || !slices.Equal(restarts, []int64{1, 3}) {
		t.Fatalf("head %+v, restarts %v, %v", head, restarts, err)
	}
	// A stored head behind the lines written (a run whose head was lost) shows as a break, never as a clean chain.
	stale := &store{head: Head{Epoch: 1, Seq: 1, Hash: hashOf(first[0])}}
	again, _ := run(t, stale, 1)
	if _, _, err := Verify(append(slices.Clone(first), again...), &Head{}); !errors.Is(err, ErrBroken) {
		t.Fatalf("a reused sequence number: %v", err)
	}
}

func TestAnEventWhoseHeadCannotBeStoredIsNotWritten(t *testing.T) {
	s := &store{}
	_, c := run(t, s, 1)
	before := c.Head()
	var buf bytes.Buffer
	c = NewChain(&buf, s.head, s.save)
	s.fail = true
	ev, _ := New("edge-a", "relikey.account.created.v1", "account:edge-a/ann", Success, Info, "", at, nil)
	if err := c.Emit(ev); err == nil || buf.Len() != 0 || c.Head() != before {
		t.Fatalf("err %v, %d bytes written, head %+v", err, buf.Len(), c.Head())
	}
}

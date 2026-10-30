// SPDX-License-Identifier: EUPL-1.2

package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"
)

// Head is where an event chain stands: the epoch of the last record, its sequence number and the sha256 of its line
// as written (decision 0025 point 2). The zero Head is a chain with no record yet.
type Head struct {
	Epoch int64  `json:"epoch"`
	Seq   int64  `json:"seq"`
	Hash  string `json:"hash"`
}

// Chain writes events as JSON lines, each carrying its sequence number (OCSF metadata.sequence, with the event's id
// as metadata.uid) and, in data.unmapped.chain, its epoch and the sha256 of the line before it ("prev"; empty for the
// first record ever). Each run that emits opens a new epoch, one above the last stored, so a restart shows in the
// stream; the sequence goes on across it. A verifier holding the lines and a later head detects a record removed,
// reordered, altered or replaced (Verify).
//
// The head is stored before its line is written: a crash between the two leaves one number unused, which a verifier
// sees as a gap at the next epoch, never a number used twice. When the head cannot be stored the event is not written.
type Chain struct {
	mu      sync.Mutex
	w       io.Writer
	save    func(Head) error
	head    Head
	started bool
}

// NewChain continues from last, the head stored by the previous run; save stores a head durably.
func NewChain(w io.Writer, last Head, save func(Head) error) *Chain {
	return &Chain{w: w, head: last, save: save}
}

// Head is the last record written (or, before this run wrote one, the one stored).
func (c *Chain) Head() Head {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}

// Emit writes e as the next record, one Write per line.
func (c *Chain) Emit(e Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := Head{Epoch: c.head.Epoch, Seq: c.head.Seq + 1}
	if !c.started {
		next.Epoch++
	}
	data := maps.Clone(e.Data)
	if data == nil {
		data = map[string]any{}
	}
	meta, _ := data["metadata"].(map[string]any)
	meta = maps.Clone(meta) // the caller's maps stay as they were
	if meta == nil {
		meta = map[string]any{}
	}
	meta["sequence"], meta["uid"] = next.Seq, e.ID
	unmapped, _ := data["unmapped"].(map[string]any)
	unmapped = maps.Clone(unmapped)
	if unmapped == nil {
		unmapped = map[string]any{}
	}
	unmapped["chain"] = map[string]any{"epoch": next.Epoch, "prev": c.head.Hash}
	data["metadata"], data["unmapped"] = meta, unmapped
	e.Data = data
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(line)
	next.Hash = hex.EncodeToString(sum[:])
	if err := c.save(next); err != nil {
		return fmt.Errorf("the event chain head could not be stored, so the event was not written: %w", err)
	}
	c.head, c.started = next, true
	_, err = c.w.Write(append(line, '\n'))
	return err
}

// link is what Verify reads from a line.
type link struct {
	Data struct {
		Metadata struct {
			Sequence *int64 `json:"sequence"`
		} `json:"metadata"`
		Unmapped struct {
			Chain *struct {
				Epoch int64   `json:"epoch"`
				Prev  *string `json:"prev"`
			} `json:"chain"`
		} `json:"unmapped"`
	} `json:"data"`
}

// ErrBroken is wrapped by every error Verify returns for a line that does not follow the one before it.
var ErrBroken = errors.New("the event chain is broken")

// Verify checks lines of one edge's event stream, in the order written, against from: the head the verifier already
// holds (the zero Head when the stream starts at the first record ever), or nil to take the first line as given.
// It returns the head after the last line, to compare with a head reported later (status.json), and the sequence
// numbers at which a new epoch began (a restart of the agent). A line whose sequence is not one above the line
// before is a record removed or reordered; a line whose prev is not the hash of the line before is a record altered
// or replaced; an epoch never goes down. A gap right at a new epoch can also be a crash between storing a head and
// writing its line.
func Verify(lines [][]byte, from *Head) (Head, []int64, error) {
	var head Head
	if from != nil {
		head = *from
	}
	var restarts []int64
	for i, raw := range lines {
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		var l link
		if err := json.Unmarshal(raw, &l); err != nil {
			return head, restarts, fmt.Errorf("%w: line %d is not JSON: %v", ErrBroken, i+1, err)
		}
		c, seq := l.Data.Unmapped.Chain, l.Data.Metadata.Sequence
		if c == nil || c.Prev == nil || seq == nil {
			return head, restarts, fmt.Errorf("%w: line %d carries no sequence or chain link", ErrBroken, i+1)
		}
		if i > 0 || from != nil {
			switch {
			case *seq != head.Seq+1:
				return head, restarts, fmt.Errorf("%w: line %d has sequence %d after %d: a record is missing or "+
					"out of order", ErrBroken, i+1, *seq, head.Seq)
			case *c.Prev != head.Hash:
				return head, restarts, fmt.Errorf("%w: line %d does not chain to the record before it: a record "+
					"was altered or replaced", ErrBroken, i+1)
			case c.Epoch < head.Epoch:
				return head, restarts, fmt.Errorf("%w: line %d goes back from epoch %d to %d", ErrBroken, i+1,
					head.Epoch, c.Epoch)
			case c.Epoch > head.Epoch:
				restarts = append(restarts, *seq)
			}
		}
		sum := sha256.Sum256(raw)
		head = Head{Epoch: c.Epoch, Seq: *seq, Hash: hex.EncodeToString(sum[:])}
	}
	return head, restarts, nil
}

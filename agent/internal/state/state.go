// SPDX-License-Identifier: EUPL-1.2

// Package state keeps what an edge must not lose: the floors (bundle serial, newest
// signed time, ceiling serial), the last verified bundle and the applied serial.
//
// Two slots (A/B), each a generation number, a sha256 and the record. A write goes to
// the slot not holding the newest generation: a temporary file, fsync, rename, fsync of
// the directory. A torn or reverted write leaves the other slot readable. Floors only
// rise. Unreadable state fails closed: losing the floors is a reinstall
// (docs/go-engineering.md, State on disk; GE-14, GE-15).
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"runtime"
	"sync"

	"relikey/agent/internal/kcedge"
)

// Record is the state of one edge.
type Record struct {
	Floors        kcedge.State   `json:"floors"`
	AppliedSerial int64          `json:"applied_serial"`
	Bundle        *kcedge.Sealed `json:"bundle,omitempty"`
	// Where the newest bundle was verified, to bound elapsed time without trusting the
	// wall clock: the boot it happened in and the boot clock then (decision 0007 point 4).
	BootID       string `json:"boot_id,omitempty"`
	BootAtVerify int64  `json:"boot_at_verify_ns,omitempty"`
	WallAtVerify string `json:"wall_at_verify,omitempty"`
	// Ended is set when the desk sent a valid ended notice: nothing is live again.
	Ended bool `json:"ended,omitempty"`
}

type slot struct {
	Gen    int64          `json:"gen"`
	SHA256 string         `json:"sha256"`
	Body   jsontext.Value `json:"body"`
}

var slots = [2]string{"state-a.json", "state-b.json"}

// maxSlot holds the largest bundle the KeyClerk client accepts (16 MiB) as base64 with room
// to spare; Save refuses a record larger than this, so nothing written is unloadable.
const maxSlot = 48 << 20

// Store is the state directory. One Store per directory and process.
type Store struct {
	mu   sync.Mutex
	root *os.Root
	gen  int64
	cur  int // index of the slot holding gen; -1 when empty
	rec  Record
	// unlock releases the exclusive lock: two agents on one directory would interleave
	// generations and could lower the floors (AG-12).
	unlock func()
}

// Open opens the state directory. Unless lab is set it refuses a directory others can
// read and, on Linux, one on tmpfs or overlay (the floors would not survive).
func Open(dir string, lab bool) (*Store, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("state directory %s: %w (create it 0700, owned by the agent's user)", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("state directory %s is not a directory", dir)
	}
	if !lab {
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("state directory %s is %v: make it 0700 so only the agent's user can read it", dir, fi.Mode().Perm())
		}
		if err := checkDurable(dir); err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	unlock, err := lockDir(root)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("state directory %s: %w", dir, err)
	}
	s := &Store{root: root, cur: -1, unlock: unlock}
	if err := s.load(); err != nil {
		unlock()
		root.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the lock and the directory.
func (s *Store) Close() error {
	s.unlock()
	return s.root.Close()
}

// Get returns the newest record (zero for a fresh install).
func (s *Store) Get() Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec
}

func (s *Store) load() error {
	present, valid := 0, 0
	for i, name := range slots {
		b, err := s.read(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		present++
		if err != nil {
			continue
		}
		var sl slot
		if json.Unmarshal(b, &sl) != nil {
			continue
		}
		sum := sha256.Sum256(sl.Body)
		if hex.EncodeToString(sum[:]) != sl.SHA256 {
			continue
		}
		var r Record
		if json.Unmarshal(sl.Body, &r) != nil {
			continue
		}
		valid++
		if s.cur == -1 || sl.Gen > s.gen {
			s.gen, s.cur, s.rec = sl.Gen, i, r
		}
	}
	if present > 0 && valid == 0 {
		return errors.New("the edge state is unreadable in both slots: refusing to start without floors " +
			"(restore the state directory from a backup, or re-enrol the edge)")
	}
	return nil
}

func (s *Store) read(name string) ([]byte, error) {
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSlot+1))
	if err == nil && len(b) > maxSlot {
		err = errors.New("state slot too large")
	}
	return b, err
}

// ErrFloorDown is returned when a write would lower a floor.
var ErrFloorDown = errors.New("a floor would go down")

// Save writes r as the next generation. It refuses to lower any floor.
func (s *Store) Save(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.rec.Floors
	if r.Floors.Serial < old.Serial || r.Floors.CeilingSerial < old.CeilingSerial ||
		(old.Newest != "" && r.Floors.Newest < old.Newest) { // fixed-width UTC times sort as strings
		return fmt.Errorf("%w: serial %d->%d, ceiling %d->%d, newest %q->%q", ErrFloorDown,
			old.Serial, r.Floors.Serial, old.CeilingSerial, r.Floors.CeilingSerial, old.Newest, r.Floors.Newest)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	out, err := json.Marshal(slot{Gen: s.gen + 1, SHA256: hex.EncodeToString(sum[:]), Body: body})
	if err != nil {
		return err
	}
	if len(out) > maxSlot {
		return fmt.Errorf("the edge state would be %d bytes, over the %d a restart can read: not written", len(out), maxSlot)
	}
	next := 0
	if s.cur == 0 {
		next = 1
	}
	if err := s.write(slots[next], out); err != nil {
		// After a failed fsync Linux may drop the dirty pages: never trust the write,
		// re-read from disk on the next start.
		return fmt.Errorf("writing the edge state: %w", err)
	}
	s.gen, s.cur, s.rec = s.gen+1, next, r
	return nil
}

func (s *Store) write(name string, b []byte) error {
	tmp := name + ".tmp"
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(b)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := s.root.Rename(tmp, name); err != nil {
		return err
	}
	if runtime.GOOS == "windows" { // directories cannot be fsynced there (development only)
		return nil
	}
	d, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

var moduleName = regexp.MustCompile(`^[0-9a-f]{64}$`)

// WriteModule keeps a verified policy module by its sha256 (KeyClerk 0.23.0 names
// modules by hash; the agent fetches each once per policy change, not every pull).
func (s *Store) WriteModule(sha256hex string, b []byte) error {
	if !moduleName.MatchString(sha256hex) {
		return fmt.Errorf("%q is not a module hash", sha256hex)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write("module-"+sha256hex+".wasm", b)
}

// HasModule says whether a module with this hash is kept.
func (s *Store) HasModule(sha256hex string) bool {
	if !moduleName.MatchString(sha256hex) {
		return false
	}
	_, err := s.root.Stat("module-" + sha256hex + ".wasm")
	return err == nil
}

// WriteStatus replaces status.json or status.html in the state directory (atomically,
// outside the slots).
func (s *Store) WriteStatus(name string, b []byte) error {
	if name != "status.json" && name != "status.html" && name != "metrics.prom" {
		return fmt.Errorf("%s is not a status file", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(name, b)
}

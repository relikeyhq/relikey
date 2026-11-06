// SPDX-License-Identifier: EUPL-1.2

// Package enrolkey holds the edge's enrolment key and its rotation (decision 0026 point 3, #26).
//
// The desk rotates the key (KeyClerk rotate_edge): the operator makes the new key (relikey-agent keygen), the edge
// co-signs the desk's rotation statement with it (relikey-agent cosign -key NEW), and both are staged in agent.json
// (next_enrolment_key_file, rotation_statement_file). Once the desk's security officer completes the rotation, the desk
// refuses the old key with 401 and sends no notice. The agent then signs the refused request again with the staged
// key; only when the desk takes it is the staged key promoted: the next key's file replaces the enrolment key's file
// by one rename, and every desk request is signed with it from then on. A 401 the next key does not cure changes
// nothing.
//
// The fleet trusts its own officers, not the desk's, so it keeps the old key until one of them approves the handover
// (fleetproto.Handover). Until then the old key stays in a sibling file, enrolment_key_file + ".old", and fleet reports
// are signed with it; once the fleet takes the new key, the old file is deleted. Without a fleet there is nothing to
// hand over and the old key goes at once.
//
// Crash safety: the old key is written to its own file before the swap, and the swap is one rename in one directory.
// A restart after the old copy but before the swap finds the old file equal to the current one, removes it and starts
// over; a restart after the swap starts with the new key and the handover pending.
package enrolkey

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"relikey/agent/internal/kcedge"
	"relikey/agent/pkg/fleetproto"
)

// OldSuffix names the old key's file beside the enrolment key's while the fleet has not taken the new key.
const OldSuffix = ".old"

// Options are the files and the facts a staged rotation is checked against.
type Options struct {
	Current   string // enrolment_key_file: the key the desk holds
	Next      string // next_enrolment_key_file: the staged key; empty when no rotation is configured
	Statement string // rotation_statement_file: the desk's rotation statement, co-signed with the next key
	Edge      string // the edge's id: the statement must be for it
	// OfficerKey is the pinned officer key (pins.officer_key): a rotation that also changes the officer is refused,
	// because the agent verifies the edge's ceiling with this pin.
	OfficerKey string
	// HoldOld keeps the old key until the fleet takes the new one; set when a fleet is configured.
	HoldOld bool
	// Read reads a key file and refuses one others can read; nil reads it plainly (tests).
	Read func(path string) (string, error)
	Log  *slog.Logger
}

// Keys is the edge's enrolment key, the staged next key, and the old key kept for the fleet. Safe for the desk's and
// the fleet's clients at once.
type Keys struct {
	o         Options
	statement fleetproto.Statement

	mu                 sync.Mutex
	current, next, old ed25519.PrivateKey
}

func (o Options) old() string { return o.Current + OldSuffix }

func (o Options) read(path string) (ed25519.PrivateKey, error) {
	var s string
	var err error
	if o.Read != nil {
		s, err = o.Read(path)
	} else {
		var b []byte
		b, err = os.ReadFile(path)
		s = strings.TrimSpace(string(b))
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not an Ed25519 seed of 64 hex characters, so the agent cannot sign with it; restore "+
			"the enrolment key from the edge's backup (a staged next key is made again with relikey-agent keygen, and "+
			"the desk's rotation with it)", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// optional reads a key file that may be absent (nil, nil).
func (o Options) optional(path string) (ed25519.PrivateKey, error) {
	k, err := o.read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return k, err
}

func hexPub(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

// Load reads the keys and checks a staged rotation. It refuses, with what completes the task: a next key outside the
// enrolment key's directory (the swap must be one rename), a key directory the swap could not rename in (#134; a
// warning only when nothing is staged), a next key without its statement or the reverse, a next
// key equal to the one in use, a statement that does not rotate this edge to the staged key, one that changes the
// edge's officer, and a second rotation staged before the fleet took the first.
func Load(o Options) (*Keys, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	k := &Keys{o: o}
	var err error
	if k.current, err = o.read(o.Current); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("enrolment_key_file %s does not exist: an edge pod installed before #134 keeps the "+
				"key in deploy/secrets/enrolment.key; move it with python deploy/edge/install.py move-keys. Otherwise "+
				"restore the enrolment key from the edge's backup (%w)", o.Current, err)
		}
		return nil, err
	}
	if k.old, err = o.optional(o.old()); err != nil {
		return nil, err
	}
	switch {
	case k.old != nil && k.old.Equal(k.current):
		// A promotion that stopped after keeping the old key and before the swap: the swap never happened.
		if err := os.Remove(o.old()); err != nil {
			return nil, fmt.Errorf("%s: a copy of the key in use, left by an interrupted promotion, cannot be removed "+
				"(%w): remove it by hand", o.old(), err)
		}
		k.old = nil
	case k.old != nil && !o.HoldOld:
		k.retire("no fleet is configured, so there is no one to hand the new key over to")
	}
	if (o.Next == "") != (o.Statement == "") {
		return nil, errors.New("next_enrolment_key_file and rotation_statement_file go together: the staged key and " +
			"the desk's rotation statement co-signed with it (relikey-agent cosign -key NEXT); set both, or neither")
	}
	swapErr := swappable(o.Current) // #134: known at start, not after the desk has taken the new key
	if o.Next == "" {
		if swapErr != nil {
			o.Log.Warn("the enrolment key is kept where a rotation could not finish; nothing is staged, so the agent "+
				"runs on", "err", swapErr)
		}
		return k, nil
	}
	if filepath.Clean(filepath.Dir(o.Next)) != filepath.Clean(filepath.Dir(o.Current)) {
		return nil, fmt.Errorf("next_enrolment_key_file %s: put it in the directory of enrolment_key_file (%s), so the "+
			"key swap is one atomic rename", o.Next, filepath.Dir(o.Current))
	}
	if swapErr != nil {
		return nil, swapErr
	}
	if k.next, err = o.optional(o.Next); err != nil {
		return nil, err
	}
	var names ed25519.PrivateKey // the key the statement must name: the staged one, or the promoted one still handed over
	switch {
	case k.next != nil && k.next.Equal(k.current):
		return nil, fmt.Errorf("next_enrolment_key_file %s holds the key in use: make a new key with relikey-agent "+
			"keygen -out %s and have the desk rotate to it", o.Next, o.Next)
	case k.next != nil && k.old != nil:
		return nil, fmt.Errorf("a next key is staged in %s while the fleet has not taken the last one (%s is kept "+
			"until it does): an officer approves the pending rotation on the fleet page first; until then remove "+
			"next_enrolment_key_file and rotation_statement_file from agent.json", o.Next, o.old())
	case k.next != nil:
		names = k.next
	case k.old != nil:
		names = k.current
	default:
		return k, nil // the rotation is complete: nothing staged, nothing to hand over
	}
	if k.statement, err = readStatement(o, names); err != nil {
		return nil, err
	}
	if k.next != nil {
		o.Log.Info("a next enrolment key is staged: the desk's first 401 is retried with it", "next_key_id",
			kcedge.KeyID(hexPub(k.next)))
	}
	return k, nil
}

func readStatement(o Options, names ed25519.PrivateKey) (fleetproto.Statement, error) {
	b, err := os.ReadFile(o.Statement)
	if err != nil {
		return fleetproto.Statement{}, err
	}
	var st fleetproto.Statement
	if err := json.Unmarshal(b, &st, json.RejectUnknownMembers(true)); err != nil {
		return st, fmt.Errorf("rotation_statement_file %s is not a multi-signed statement: %w", o.Statement, err)
	}
	f, err := fleetproto.CheckStatement(st, o.Edge, hexPub(names))
	if err != nil {
		return st, fmt.Errorf("rotation_statement_file %s: %w; give the statement of this rotation, co-signed with "+
			"the staged key (relikey-agent cosign -key %s)", o.Statement, err, o.Next)
	}
	if f.OfficerKey != o.OfficerKey {
		return st, fmt.Errorf("rotation_statement_file %s names officer key %s, but pins.officer_key is %s: a rotation "+
			"that also changes the edge's officer is not supported, because the agent verifies the edge's ceiling with "+
			"the pinned officer key (#26). Ask the desk for a rotation under the officer the edge pins; an officer change "+
			"needs the edge enrolled again", o.Statement, kcedge.KeyID(f.OfficerKey), kcedge.KeyID(o.OfficerKey))
	}
	return st, nil
}

// Current is the key the desk holds: every desk request is signed with it.
func (k *Keys) Current() ed25519.PrivateKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.current
}

// Next is the staged key, nil when none is staged.
func (k *Keys) Next() ed25519.PrivateKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.next
}

// Promote makes the staged key the current one, after the desk took a request signed with it. Two requests may race
// to it: the second finds nothing staged and does nothing. When the files cannot be swapped, nothing changes and the
// log says why: the next desk request is refused once more and retried with the staged key.
func (k *Keys) Promote(next ed25519.PrivateKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.next == nil || !k.next.Equal(next) {
		return
	}
	if err := k.swap(); err != nil {
		k.o.Log.Error("the desk takes the next enrolment key, but it could not be made the edge's key: each desk "+
			"request is refused once more and retried with it until this works", "err", err,
			"next", "check that the agent can write the directory of enrolment_key_file")
		return
	}
	was := k.current
	k.current, k.next = next, nil
	held := "deleted: no fleet is configured"
	if k.o.HoldOld {
		k.old = was
		held = "kept in " + k.o.old() + " until an officer approves the rotation on the fleet page"
	}
	k.o.Log.Warn("the desk took the next enrolment key: it is the edge's enrolment key from now on", "key_id",
		kcedge.KeyID(hexPub(next)), "old_key_id", kcedge.KeyID(hexPub(was)), "old_key", held)
}

// swap keeps the old key in its own file when the fleet still needs it, then renames the next key's file over the
// enrolment key's. The old copy comes first: a crash between the two leaves it equal to the current key, which Load
// reads as a swap that never happened.
func (k *Keys) swap() error {
	if k.o.HoldOld {
		if err := writeKey(k.o.old(), k.current); err != nil {
			return err
		}
	}
	if err := os.Rename(k.o.Next, k.o.Current); err != nil {
		return err
	}
	return syncDir(filepath.Dir(k.o.Current))
}

// FleetKeys is the key the fleet holds and, while it has not taken the new key, the new key (fleetproto.Rotation).
func (k *Keys) FleetKeys() (held, next ed25519.PrivateKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.old != nil {
		return k.old, k.current
	}
	return k.current, nil
}

// Statement is the desk's rotation statement the handover carries.
func (k *Keys) Statement() fleetproto.Statement { return k.statement }

// Retire deletes the old key: the fleet took the new one.
func (k *Keys) Retire() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.retire("the fleet took the new enrolment key")
}

func (k *Keys) retire(why string) {
	if k.old == nil {
		return
	}
	id := kcedge.KeyID(hexPub(k.old))
	k.old = nil
	err := os.Remove(k.o.old())
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		err = syncDir(filepath.Dir(k.o.Current))
	}
	if err != nil {
		// Left behind, the file is read at the next start as a rotation still being handed over; the fleet then
		// refuses the old key and the agent retires it again.
		k.o.Log.Error(why+", but the old enrolment key could not be deleted", "file", k.o.old(), "err", err,
			"next", "delete the file by hand")
		return
	}
	k.o.Log.Info(why+": the old enrolment key is deleted", "old_key_id", id, "file", k.o.old())
}

// writeKey writes a key file whole: a temporary file, synced, renamed over the name.
func writeKey(path string, key ed25519.PrivateKey) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(key.Seed()) + "\n"); err != nil {
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
	return os.Rename(tmp, path)
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" { // directories cannot be fsynced there (development only)
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// SPDX-License-Identifier: EUPL-1.2

package enrolkey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/kcedge"
)

// rig is an edge's key directory: the enrolment key, a staged next key and the desk's rotation statement for it.
type rig struct {
	dir                  string
	cur, next, officer   ed25519.PrivateKey
	curF, nextF, stmtF   string
	log                  bytes.Buffer
	holdOld              bool
	officerPin, edgeName string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{dir: t.TempDir(), cur: fakes.Key(9), next: fakes.Key(10), officer: fakes.Key(2), holdOld: true, edgeName: "edge-a"}
	g.officerPin = fakes.Hex(g.officer)
	g.curF, g.nextF, g.stmtF = filepath.Join(g.dir, "enrolment.key"), filepath.Join(g.dir, "enrolment.next.key"),
		filepath.Join(g.dir, "rotation.json")
	g.put(g.curF, g.cur)
	g.put(g.nextF, g.next)
	g.statement(t, nil)
	return g
}

func (g *rig) put(path string, k ed25519.PrivateKey) {
	_ = os.WriteFile(path, []byte(hex.EncodeToString(k.Seed())+"\n"), 0o600)
}

func (g *rig) statement(t *testing.T, change func(kcedge.Object)) {
	t.Helper()
	if err := os.WriteFile(g.stmtF, fakes.RotationStatement(g.edgeName, g.officer, g.next, change), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (g *rig) opts() Options {
	return Options{Current: g.curF, Next: g.nextF, Statement: g.stmtF, Edge: "edge-a", OfficerKey: g.officerPin,
		HoldOld: g.holdOld, Log: slog.New(slog.NewTextHandler(&g.log, nil))}
}

func (g *rig) load(t *testing.T) *Keys {
	t.Helper()
	k, err := Load(g.opts())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return k
}

func seedOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// A staged rotation loads: the desk is signed with the current key, the next one waits, the fleet holds the current.
func TestAStagedRotationLoads(t *testing.T) {
	g := newRig(t)
	k := g.load(t)
	if !k.Current().Equal(g.cur) || !k.Next().Equal(g.next) {
		t.Fatal("the current and next keys are not the files'")
	}
	if held, next := k.FleetKeys(); !held.Equal(g.cur) || next != nil {
		t.Fatal("before the promotion the fleet holds the current key and nothing is handed over")
	}
}

// Promotion swaps the files atomically and keeps the old key for the fleet; a restart after it starts with the new
// key and the handover pending; the fleet's acceptance deletes the old key.
func TestPromotionSwapsTheFilesAndARestartKeepsTheNewKey(t *testing.T) {
	g := newRig(t)
	k := g.load(t)
	k.Promote(g.next)
	if !k.Current().Equal(g.next) || k.Next() != nil {
		t.Fatal("after the promotion the next key is not the current one")
	}
	if seedOf(t, g.curF) != hex.EncodeToString(g.next.Seed()) || exists(g.nextF) {
		t.Fatal("the next key's file did not replace the enrolment key's")
	}
	if seedOf(t, g.curF+OldSuffix) != hex.EncodeToString(g.cur.Seed()) {
		t.Fatal("the old key is not kept for the fleet")
	}
	if held, next := k.FleetKeys(); !held.Equal(g.cur) || !next.Equal(g.next) {
		t.Fatal("until the fleet takes it, the fleet holds the old key and the new one is handed over")
	}
	again := g.load(t) // a restart after the promotion
	if !again.Current().Equal(g.next) || again.Next() != nil {
		t.Fatal("a restart after the promotion does not start with the new key")
	}
	if held, next := again.FleetKeys(); !held.Equal(g.cur) || !next.Equal(g.next) {
		t.Fatal("a restart after the promotion lost the pending handover")
	}
	again.Retire()
	if exists(g.curF + OldSuffix) {
		t.Fatal("the old key file is not deleted when the fleet took the new key")
	}
	if held, next := again.FleetKeys(); !held.Equal(g.next) || next != nil {
		t.Fatal("after the fleet took the new key it is the fleet's key too")
	}
	if !strings.Contains(g.log.String(), "the old enrolment key is deleted") {
		t.Fatalf("the deletion is not logged: %s", g.log.String())
	}
}

// A promotion that stopped after keeping the old key and before the swap leaves the old file equal to the current
// one: a restart reads it as a swap that never happened, removes the copy and keeps the next key staged.
func TestAnInterruptedPromotionStartsOver(t *testing.T) {
	g := newRig(t)
	g.put(g.curF+OldSuffix, g.cur)
	k := g.load(t)
	if exists(g.curF+OldSuffix) || !k.Current().Equal(g.cur) || !k.Next().Equal(g.next) {
		t.Fatal("an interrupted promotion is not started over")
	}
	if _, next := k.FleetKeys(); next != nil {
		t.Fatal("an interrupted promotion is taken as a handover")
	}
}

// A promotion that cannot swap the files changes nothing and says why; another key or a second promotion does nothing.
func TestAFailedOrForeignPromotionChangesNothing(t *testing.T) {
	g := newRig(t)
	k := g.load(t)
	k.Promote(fakes.Key(11))
	if !k.Current().Equal(g.cur) || !k.Next().Equal(g.next) {
		t.Fatal("a key that is not the staged one was promoted")
	}
	_ = os.Remove(g.nextF) // the rename has nothing to move
	k.Promote(g.next)
	if !k.Current().Equal(g.cur) || !k.Next().Equal(g.next) || seedOf(t, g.curF) != hex.EncodeToString(g.cur.Seed()) {
		t.Fatal("a promotion whose swap failed changed the keys")
	}
	if !strings.Contains(g.log.String(), "could not be made the edge's key") {
		t.Fatalf("the failed swap is not logged: %s", g.log.String())
	}
	g.put(g.nextF, g.next)
	k.Promote(g.next)
	k.Promote(g.next) // a second request racing to the same promotion
	if !k.Current().Equal(g.next) || seedOf(t, g.curF) != hex.EncodeToString(g.next.Seed()) {
		t.Fatal("the promotion did not happen once the files could be swapped")
	}
}

// Without a fleet nothing is handed over: the promotion keeps no old key, and an old key left behind is deleted.
func TestWithoutAFleetTheOldKeyGoesAtOnce(t *testing.T) {
	g := newRig(t)
	g.holdOld = false
	k := g.load(t)
	k.Promote(g.next)
	if exists(g.curF + OldSuffix) {
		t.Fatal("an old key was kept with no fleet to hand it over to")
	}
	if _, next := k.FleetKeys(); next != nil {
		t.Fatal("a handover is pending with no fleet")
	}
	g.put(g.curF+OldSuffix, g.cur)
	_ = g.load(t)
	if exists(g.curF + OldSuffix) {
		t.Fatal("an old key left behind is kept with no fleet")
	}
}

// Each misconfigured rotation is refused at start with what completes it.
func TestAMisconfiguredRotationIsRefusedWithTheNextStep(t *testing.T) {
	for _, tc := range []struct {
		name, want, next string
		set              func(*rig, *Options)
	}{
		{"a next key without its statement", "go together", "set both, or neither",
			func(_ *rig, o *Options) { o.Statement = "" }},
		{"a statement without a next key", "go together", "set both, or neither",
			func(_ *rig, o *Options) { o.Next = "" }},
		{"a next key in another directory", "put it in the directory of enrolment_key_file", "one atomic rename",
			func(g *rig, o *Options) {
				o.Next = filepath.Join(t.TempDir(), "next.key")
				g.put(o.Next, g.next)
			}},
		{"a next key equal to the current", "holds the key in use", "relikey-agent keygen",
			func(g *rig, _ *Options) { g.put(g.nextF, g.cur) }},
		{"a statement for another key", "does not name the new key", "relikey-agent cosign",
			func(g *rig, _ *Options) { g.put(g.nextF, fakes.Key(12)) }},
		{"a statement for another edge", `for edge "edge-b"`, "relikey-agent cosign",
			func(g *rig, _ *Options) { g.edgeName = "edge-b"; g.statement(t, nil) }},
		{"an enrolment statement", "not rotation", "rotate_edge",
			func(g *rig, _ *Options) { g.statement(t, func(o kcedge.Object) { o["purpose"] = "enrolment" }) }},
		{"a rotation that changes the officer", "changes the edge's officer is not supported",
			"Ask the desk for a rotation under the officer the edge pins",
			func(g *rig, o *Options) { o.OfficerKey = fakes.Hex(fakes.Key(3)) }},
		{"a second rotation before the fleet took the first", "the fleet has not taken the last one",
			"an officer approves the pending rotation on the fleet page first",
			func(g *rig, _ *Options) { g.put(g.curF+OldSuffix, fakes.Key(13)) }},
		{"an unreadable enrolment key", "not an Ed25519 seed", "restore the enrolment key",
			func(g *rig, _ *Options) { _ = os.WriteFile(g.curF, []byte("nonsense\n"), 0o600) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			o := g.opts()
			tc.set(g, &o)
			_, err := Load(o)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.next) {
				t.Fatalf("got %v, want an error saying %q and %q", err, tc.want, tc.next)
			}
		})
	}
}

// A completed rotation leaves nothing to stage or hand over, even with the settings still in agent.json.
func TestACompletedRotationNeedsNothing(t *testing.T) {
	g := newRig(t)
	g.put(g.curF, g.next)
	_ = os.Remove(g.nextF)
	_ = os.Remove(g.stmtF)
	k := g.load(t)
	if k.Next() != nil {
		t.Fatal("a completed rotation stages a key")
	}
	if held, next := k.FleetKeys(); !held.Equal(g.next) || next != nil {
		t.Fatal("a completed rotation hands something over")
	}
}

// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"relikey/agent/internal/bastion"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"relikey/agent/internal/apply"
	"relikey/agent/internal/clock"
	"relikey/agent/internal/fakes"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/internal/state"
	"relikey/agent/internal/warpgate"
	"relikey/agent/pkg/events"
	"relikey/agent/pkg/fleetproto"
)

type rig struct {
	tune   func(*Agent) // changes the agent before it runs
	mu     sync.Mutex
	events []events.Event
	lines  [][]byte // the event lines as written
	t      *testing.T
	kc     *fakes.KeyClerk
	wg     *fakes.Warpgate
	dir    string
	store  *state.Store
	mode   Mode
	enrol  ed25519.PrivateKey
	kcURL  string
	kcPin  string
	wgURL  string
	wgPin  string
	stop   context.CancelFunc
	done   chan struct{}
}

func newRig(t *testing.T, mode Mode) *rig {
	t.Helper()
	r := newRigOff(t, mode, nil)
	r.start()
	t.Cleanup(r.halt)
	return r
}

// newRigOff is a rig whose agent does not run yet: start runs it, or a test builds it and drives it alone.
func newRigOff(t *testing.T, mode Mode, tune func(*Agent)) *rig {
	t.Helper()
	r := &rig{t: t, dir: t.TempDir(), mode: mode, enrol: fakes.Key(9), tune: tune}
	r.kc = fakes.NewKeyClerk("edge-a", r.enrol.Public().(ed25519.PublicKey), []string{"idp:ann"}, []string{"plc"})
	r.wg = fakes.NewWarpgate("tok", map[string][]string{"plc-operator": {"plc"}})
	kcSrv, kcURL, kcPin := r.kc.Serve()
	wgSrv, wgURL, wgPin := r.wg.Serve()
	t.Cleanup(kcSrv.Close)
	t.Cleanup(wgSrv.Close)
	r.kcURL, r.kcPin, r.wgURL, r.wgPin = kcURL, kcPin, wgURL, wgPin
	return r
}

func (r *rig) start() {
	a := r.agent()
	ctx, cancel := context.WithCancel(context.Background())
	r.stop, r.done = cancel, make(chan struct{})
	go func() { defer close(r.done); _ = a.Run(ctx) }()
}

// agent opens the store and builds the agent. The status heartbeat is a nanosecond, so the tests that wait for ticks
// in status.json see every tick; the tests of the heartbeat set their own.
func (r *rig) agent() *Agent {
	var err error
	if r.store, err = state.Open(r.dir, true); err != nil {
		r.t.Fatal(err)
	}
	kcHTTP, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, PinSHA256: r.kcPin})
	wgHTTP, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, PinSHA256: r.wgPin})
	clk := clock.System{}
	a := &Agent{Pins: r.kc.Pins(), Provider: "keycloak", Mode: r.mode, Version: "relikey-agent test 0123456789ab go1.27.3", Release: "test", Store: r.store, Clock: clk,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clerk:   &keyclerk.Client{Base: r.kcURL, Edge: "edge-a", Key: r.enrol, HTTP: kcHTTP, Now: clk.Now},
		Bastion: warpgate.Bastion{C: &warpgate.Client{Base: r.wgURL, Token: "tok", HTTP: wgHTTP, RetryBase: time.Millisecond}},
		Tick:    100 * time.Millisecond, Pull: 300 * time.Millisecond, Grace: time.Second, StatusHeartbeat: time.Nanosecond,
		Events: sink{r}}
	if r.tune != nil {
		r.tune(a)
	}
	return a
}

// sink is the agent's event stream in the tests: each Write is one line, kept as written and parsed.
type sink struct{ r *rig }

func (s sink) Write(b []byte) (int, error) {
	var e events.Event
	if err := json.Unmarshal(bytes.TrimSpace(b), &e); err != nil {
		return 0, err
	}
	s.r.mu.Lock()
	s.r.lines, s.r.events = append(s.r.lines, bytes.Clone(b)), append(s.r.events, e)
	s.r.mu.Unlock()
	return len(b), nil
}

func (r *rig) halt() {
	if r.stop != nil {
		r.stop()
		<-r.done
		r.store.Close()
		r.stop = nil
	}
}

func (r *rig) status() Status {
	var st Status
	b, _ := os.ReadFile(filepath.Join(r.dir, "status.json"))
	_ = json.Unmarshal(b, &st)
	return st
}

func (r *rig) eventually(what string, f func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.t.Fatalf("not within 10s: %s (status %+v)", what, r.status())
}

func (r *rig) roles(user string) map[string]time.Time {
	v, _ := r.wg.Snapshot(apply.Marker)
	return v[user]
}

func lease(id string, until time.Time) fakes.FakeLease {
	return fakes.FakeLease{ID: id, Person: "idp:ann", Username: "ann", Email: "ann@example.test", Target: "plc",
		Role: "plc-operator", Class: "low", From: time.Now().Add(-time.Minute), Until: until}
}

func TestALeaseIsAppliedAndReported(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.eventually("the applied serial is reported", func() bool {
		var rep keyclerk.Report
		return json.Unmarshal(r.kc.LastReport(), &rep) == nil && rep.AppliedSerial == r.kc.Serial()
	})
}

// generation is the newest generation in the state slots: every slot write raises it by one.
func (r *rig) generation() int64 {
	var gen int64
	for _, n := range []string{"state-a.json", "state-b.json"} {
		var sl struct {
			Gen int64 `json:"gen"`
		}
		b, _ := os.ReadFile(filepath.Join(r.dir, n))
		if json.Unmarshal(b, &sl) == nil {
			gen = max(gen, sl.Gen)
		}
	}
	return gen
}

// AG-14: idle ticks and pulls that bring nothing new write no state (edge hardware often boots from flash).
func TestIdleTicksWriteNoState(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("the bundle is applied", func() bool {
		st := r.status()
		return st.AppliedSerial > 0 && st.AppliedSerial == r.kc.Serial()
	})
	gen, ticks := r.generation(), r.status().Ticks
	pulls, _ := r.kc.Counts()
	r.eventually("20 idle ticks and 3 idle pulls", func() bool {
		n, _ := r.kc.Counts()
		return r.status().Ticks >= ticks+20 && n >= pulls+3
	})
	if got := r.generation(); gen == 0 || got != gen {
		t.Fatalf("idle ticks wrote the state: generation %d -> %d", gen, got)
	}
}

// Idle ticks and pulls leave the status files alone until the heartbeat, which still comes, so `updated` keeps telling
// a live agent from a stalled one (issue 54).
func TestIdleTicksWriteTheStatusOnlyAtTheHeartbeat(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) { a.StatusHeartbeat = time.Second })
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("the bundle is applied", func() bool {
		st := r.status()
		return st.AppliedSerial > 0 && st.AppliedSerial == r.kc.Serial()
	})
	first := r.status()
	pulls, _ := r.kc.Counts()
	writes := map[time.Time]bool{}
	for end := time.Now().Add(4 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if st := r.status(); !st.Updated.IsZero() && !st.Updated.Equal(first.Updated) {
			writes[st.Updated] = true
		}
	}
	last := r.status()
	if n, _ := r.kc.Counts(); last.Ticks < first.Ticks+20 || n < pulls+3 {
		t.Fatalf("not idle long enough: ticks %d -> %d, pulls %d -> %d", first.Ticks, last.Ticks, pulls, n)
	}
	// 40 ticks in 4 s at a 1 s heartbeat: about 4 writes; every tick would be about 40, none would be 0.
	if len(writes) < 2 || len(writes) > 6 {
		t.Fatalf("%d status writes over %d idle ticks, want 2 to 6 (the heartbeat)", len(writes), last.Ticks-first.Ticks)
	}
}

// A change reaches the status files at once, not at the heartbeat; nothing else is written meanwhile.
func TestTheStatusIsWrittenWhenItChanges(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) { a.StatusHeartbeat = time.Hour })
	r.eventually("the first status", func() bool { return r.status().Ticks > 0 })
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("the lease applied, nothing left over", func() bool {
		st := r.status()
		return st.LiveLeases == 1 && st.AppliedSerial > 0 && st.AppliedSerial == r.kc.Serial() && st.NonEmptyStreak == 0
	})
	before := r.status()
	time.Sleep(time.Second) // ten idle ticks, three idle pulls
	if after := r.status(); !after.Updated.Equal(before.Updated) {
		t.Fatalf("an idle second rewrote the status: ticks %d -> %d", before.Ticks, after.Ticks)
	}
}

// A bundle with a new serial but the content already held is still stored: its serial and signed time are the replay
// floors. Here the desk issued 1 (ann), 2 (ann and eve), 3 (ann again); the edge saw 1 and 3, and 2 replayed later must
// be refused, or eve's revoked lease would come back.
func TestASameContentBundleWithANewSerialRaisesTheFloor(t *testing.T) {
	r := newRigOff(t, Enforce, nil)
	a := r.agent()
	t.Cleanup(func() { r.store.Close() })
	a.defaults()
	a.st = Status{Drift: []string{}}
	ctx := context.Background()
	pull := func() keyclerk.Pulled {
		t.Helper()
		got, err := a.Clerk.Pull(ctx, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	ann := lease("L-1", time.Now().Add(time.Hour))
	eve := lease("L-2", time.Now().Add(time.Hour))
	eve.Username = "eve"
	r.kc.SetLeases([]fakes.FakeLease{ann}, nil)
	b1 := pull()
	r.kc.SetLeases([]fakes.FakeLease{ann, eve}, nil)
	b2 := pull()
	r.kc.SetLeases([]fakes.FakeLease{ann}, nil)
	b3 := pull()
	d1, _ := kcedge.ContentDigest(*b1.Bundle, a.Pins)
	d3, _ := kcedge.ContentDigest(*b3.Bundle, a.Pins)
	if d1 == "" || d1 != d3 {
		t.Fatalf("bundles 1 and 3 should have the same content: %q, %q", d1, d3)
	}
	a.handlePull(ctx, b1, nil)
	gen := r.generation()
	a.handlePull(ctx, b3, nil)
	if f := a.Store.Get().Floors.Serial; f != 3 || r.generation() <= gen {
		t.Fatalf("the same content under serial 3 was not stored: floor %d, generation %d -> %d", f, gen, r.generation())
	}
	a.handlePull(ctx, b2, nil)
	if a.st.Refused != 1 || a.Store.Get().Floors.Serial != 3 || r.roles("eve") != nil {
		t.Fatalf("bundle 2 replayed after 3 was taken: refused %d, floor %d, eve %v", a.st.Refused,
			a.Store.Get().Floors.Serial, r.roles("eve"))
	}
}

func TestTheClerksGovernedRolesAloneReportAnUnmanagedHolder(t *testing.T) {
	r := newRig(t, Enforce) // no governed-roles file: the signed catalogue in the bundle is the only source
	rogue := r.wg.AddUser("rogue", "made behind the agent's back")
	r.wg.AssignRole(rogue, "plc-operator", nil)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	if slices.ContainsFunc(r.status().Drift, func(s string) bool { return strings.Contains(s, "account rogue") }) {
		t.Fatal("reported without any source of governed roles")
	}
	r.kc.SetGoverned([]string{"plc-operator"})
	r.eventually("the holder is reported", func() bool {
		return slices.ContainsFunc(r.status().Drift, func(s string) bool {
			return strings.Contains(s, "account rogue is not managed by ReliKey but holds the governed role plc-operator")
		})
	})
	if !r.wg.UserExists("rogue", "made behind the agent's back") {
		t.Fatal("an unmanaged account was removed")
	}
}

// seen returns the types of the events emitted for a subject, in order.
func (r *rig) seen(subject string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	types := []string{}
	for _, e := range r.events {
		if e.Subject == subject {
			types = append(types, e.Type)
		}
	}
	return types
}

func TestTheAgentsChangesAreEmittedAsEvents(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann's account and role are events", func() bool {
		s := r.seen("account:edge-a/ann")
		return slices.Contains(s, "relikey.account.created.v1") && slices.Contains(s, "relikey.account.role_granted.v1")
	})
	_, err := r.wg.OpenSession("ann", "plc")
	if err != nil {
		t.Fatal(err)
	}
	r.kc.SetLeases(nil, []string{"L-1"})
	r.eventually("the closed session and the deleted account are events", func() bool {
		s := r.seen("account:edge-a/ann")
		return slices.Contains(s, "relikey.session.closed.v1") && slices.Contains(s, "relikey.account.deleted.v1")
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Data["metadata"] == nil || e.Data["class_uid"] == nil || e.Outcome == "" || e.Name != e.Type {
			t.Fatalf("an incomplete event: %+v", e)
		}
		if strings.Contains(fmt.Sprint(e.Data), "@example.test") {
			t.Fatalf("an event carries an e-mail: %+v", e)
		}
	}
}

func TestAnUnmanagedHolderIsAFindingOnceAndResolvedOnce(t *testing.T) {
	r := newRig(t, Enforce)
	rogue := r.wg.AddUser("rogue", "made behind the agent's back")
	r.kc.SetGoverned([]string{"plc-operator"})
	r.kc.SetLeases(nil, nil)
	r.wg.AssignRole(rogue, "plc-operator", nil)
	r.eventually("the finding", func() bool { return len(r.seen("account:edge-a/rogue")) == 1 })
	time.Sleep(500 * time.Millisecond) // several ticks
	if n := len(r.seen("account:edge-a/rogue")); n != 1 {
		t.Fatalf("the finding was repeated: %d events", n)
	}
	r.kc.SetGoverned([]string{})
	r.eventually("resolved", func() bool { return len(r.seen("account:edge-a/rogue")) == 2 })
	r.mu.Lock()
	defer r.mu.Unlock()
	var last events.Event
	for _, e := range r.events {
		if e.Subject == "account:edge-a/rogue" {
			last = e
		}
	}
	if last.Data["class_uid"] != float64(2003) || last.Data["status"] != "Resolved" {
		t.Fatalf("not a resolved compliance finding: %+v", last.Data)
	}
}

// newRigTuned is newRig with the agent changed before it starts.
func newRigTuned(t *testing.T, tune func(*Agent)) *rig {
	t.Helper()
	r := newRigOff(t, Enforce, tune)
	r.start()
	t.Cleanup(r.halt)
	return r
}

// With a pull interval of a minute, a grant and a revoke still reach the edge in seconds: the desk holds the
// long-poll and answers when the bundle changes (KeyClerk decision 0026).
func TestALongPollBringsGrantsAndRevokesAtOnce(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) { a.Pull, a.Wait = time.Minute, 5*time.Second })
	r.eventually("a long-poll is held", func() bool { return held(r.kc) > 0 })
	start := time.Now()
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.kc.SetLeases(nil, []string{"L-1"})
	r.eventually("ann is removed", func() bool { return r.roles("ann") == nil })
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v with a one-minute pull interval", d)
	}
}

// A desk without long-poll answers at once; the agent then keeps its interval as the floor, never a tight loop.
func TestWithoutLongPollTheIntervalIsTheFloor(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) { a.Pull, a.Wait = time.Minute, 5*time.Second })
	r.kc.SetNoLongPoll(true)
	time.Sleep(time.Second)
	if n := pulls(r.kc); n > 3 {
		t.Fatalf("%d pulls in a second against a desk that answers at once", n)
	}
}

// A desk that answers at once with a bundle the agent refuses (here: the previous one, replayed) must not drive an
// immediate re-poll: a refused answer is not a change (second red team of 0025).
func TestARefusedAnswerIsNotAChange(t *testing.T) {
	r := newRigTuned(t, func(a *Agent) { a.Pull, a.Wait = time.Minute, 5*time.Second })
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.kc.SetLeases(nil, nil) // the agent accepts this one; the desk keeps the one before as its replay
	r.eventually("ann is removed", func() bool { return r.roles("ann") == nil })
	r.kc.SetNoLongPoll(true)
	r.kc.SetFaults(false, true) // every answer now: the older bundle, other content, refused as a replay
	before := pulls(r.kc)
	time.Sleep(1500 * time.Millisecond)
	if n := pulls(r.kc) - before; n > 3 {
		t.Fatalf("%d pulls in 1.5 s against a desk answering with refused bundles", n)
	}
}

// When the governed roles cannot be read, an absence proves nothing: the finding stands, no "resolved" is emitted
// (red team of 2026-10-25).
func TestAnUncheckedTickNeverResolvesAFinding(t *testing.T) {
	var broken atomic.Bool
	r := newRigTuned(t, func(a *Agent) {
		a.Governed = func() (map[string]bool, error) {
			if broken.Load() {
				return nil, errors.New("governed-roles file unreadable")
			}
			return map[string]bool{"plc-operator": true}, nil
		}
	})
	rogue := r.wg.AddUser("rogue", "made behind the agent's back")
	r.wg.AssignRole(rogue, "plc-operator", nil)
	r.eventually("the finding", func() bool { return len(r.seen("account:edge-a/rogue")) == 1 })
	broken.Store(true)
	time.Sleep(600 * time.Millisecond) // several ticks without a readable source
	if n := len(r.seen("account:edge-a/rogue")); n != 1 {
		t.Fatalf("an unchecked tick emitted %d events for the rogue account (want the one finding)", n)
	}
	broken.Store(false)
	time.Sleep(400 * time.Millisecond)
	if n := len(r.seen("account:edge-a/rogue")); n != 1 {
		t.Fatalf("readable again, the unchanged finding was re-emitted: %d events", n)
	}
}

// The edge's file fails while the bundle still carries a catalogue: the set is incomplete, so a finding the file
// supplied is not resolved by its absence.
func TestAPartialCheckNeverResolvesAFinding(t *testing.T) {
	var broken atomic.Bool
	r := newRigTuned(t, func(a *Agent) {
		a.Governed = func() (map[string]bool, error) {
			if broken.Load() {
				return nil, errors.New("governed-roles file unreadable")
			}
			return map[string]bool{"plc-operator": true}, nil
		}
	})
	r.kc.SetGoverned([]string{"another-role"}) // the clerk's catalogue governs something else
	rogue := r.wg.AddUser("rogue", "made behind the agent's back")
	r.wg.AssignRole(rogue, "plc-operator", nil)
	r.eventually("the finding", func() bool { return len(r.seen("account:edge-a/rogue")) == 1 })
	broken.Store(true)
	time.Sleep(600 * time.Millisecond)
	if n := len(r.seen("account:edge-a/rogue")); n != 1 {
		t.Fatalf("a partial check emitted %d events for the rogue account (want the one finding)", n)
	}
}

// The agent's reports arrive signed, verify against its enrolment key, and carry its applied serial and live lease
// (decision 0026 slice 2; the fleet module tests the inventory itself).
func TestTheAgentReportsToTheFleet(t *testing.T) {
	enrol := fakes.Key(9)
	keys := map[string]ed25519.PublicKey{"edge-a": enrol.Public().(ed25519.PublicKey)}
	var mu sync.Mutex
	var got []fleetproto.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var s fleetproto.Signed
		if json.UnmarshalRead(r.Body, &s) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rep, err := fleetproto.Verify(s, keys)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		got = append(got, rep)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	r := newRigTuned(t, func(a *Agent) { a.Fleet = &fleetproto.Client{URL: srv.URL, HTTP: srv.Client(), Key: enrol} })
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("a verified report with the applied serial and the live lease", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, rep := range got {
			if rep.Edge == "edge-a" && rep.AppliedSerial >= 1 && rep.LiveLeases == 1 {
				return true
			}
		}
		return false
	})
}

// Reports go at most once per pull interval, not on every reconcile tick.
func TestFleetReportsKeepThePullInterval(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	newRigTuned(t, func(a *Agent) { a.Fleet = &fleetproto.Client{URL: srv.URL, HTTP: srv.Client(), Key: fakes.Key(9)} })
	time.Sleep(1200 * time.Millisecond) // ticks every 100 ms, pulls every 300 ms
	if got := n.Load(); got < 2 || got > 6 {
		t.Fatalf("%d reports in 1.2 s (want about one per 300 ms pull interval, never one per 100 ms tick)", got)
	}
}

// backClock is the system clock until jump is set, then an hour behind: a wall clock set back.
type backClock struct {
	clock.System
	jump *atomic.Bool
}

func (c backClock) Now() time.Time {
	if c.jump.Load() {
		return time.Now().Add(-time.Hour)
	}
	return time.Now()
}

// A clock set back must not silence the fleet reports (red team of 2026-10-25): the interval is monotonic.
func TestASetBackClockDoesNotStallFleetReports(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	var jump atomic.Bool
	newRigTuned(t, func(a *Agent) {
		a.Clock = backClock{jump: &jump}
		a.Fleet = &fleetproto.Client{URL: srv.URL, HTTP: srv.Client(), Key: fakes.Key(9)}
	})
	time.Sleep(500 * time.Millisecond)
	jump.Store(true)
	before := n.Load()
	time.Sleep(1200 * time.Millisecond)
	if got := n.Load() - before; got < 2 {
		t.Fatalf("%d reports in 1.2 s after the clock went back an hour: reports stalled", got)
	}
}

func TestARevokedLeaseEndsTheSession(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann exists", func() bool { return r.roles("ann") != nil })
	sid, err := r.wg.OpenSession("ann", "plc")
	if err != nil {
		t.Fatal(err)
	}
	r.kc.SetLeases(nil, []string{"L-1"})
	r.eventually("the session is closed", func() bool { return !r.wg.SessionOpen(sid) })
	r.eventually("ann is removed", func() bool { return r.roles("ann") == nil })
}

func TestALeaseEndsOnTheEdgeWhileTheDeskIsDown(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(3*time.Second))}, nil)
	r.eventually("ann gets the role", func() bool { return r.roles("ann") != nil })
	r.kc.SetFaults(true, false) // the agent decides alone from here
	// The outage is waited for, not asserted once at the end: under load the grant can take most of the lease's
	// three seconds, and the lease may end before a pull has failed (a flake seen once in 570 runs, 2026-10-25).
	r.eventually("the outage is seen", func() bool { return r.status().PullsFailed > 0 })
	r.eventually("the lease ends at its until", func() bool { return r.roles("ann") == nil })
}

func TestAReplayedBundleIsRefused(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("serial 1 applied", func() bool { return r.status().AppliedSerial >= 1 })
	r.kc.SetLeases(nil, nil) // serial 2: no leases
	r.eventually("serial 2 applied", func() bool { return r.status().Serial >= 2 && r.roles("ann") == nil })
	r.kc.SetFaults(false, true) // now the desk (or someone in the path) answers with serial 1 again
	r.eventually("the replay is refused", func() bool { return r.status().Refused > 0 })
	time.Sleep(400 * time.Millisecond)
	if r.roles("ann") != nil {
		t.Fatal("the replayed bundle gave access back")
	}
}

func TestAnEndedEdgeRemovesEverythingForGood(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { return r.roles("ann") != nil })
	r.kc.SetEnded(true)
	r.eventually("everything is removed", func() bool { return r.roles("ann") == nil && r.status().Ended })
	r.kc.SetEnded(false) // a bundle after the end is never taken again
	r.kc.SetLeases([]fakes.FakeLease{lease("L-2", time.Now().Add(time.Hour))}, nil)
	time.Sleep(time.Second)
	if r.roles("ann") != nil {
		t.Fatal("an ended edge took a bundle again")
	}
}

// AG-18 (KeyClerk 0.23.0): an ended notice names the enrolment keys it ends; one for
// another key (a captured notice of an earlier enrolment) is refused and access stays.
func TestAnEndedNoticeForAnotherEnrolmentKeyIsIgnored(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { return r.roles("ann") != nil })
	r.kc.SetEndedFor([]string{"0123456789abcdef"})
	r.eventually("the notice is refused", func() bool {
		return strings.Contains(r.status().LastRefusal, "not this node")
	})
	if r.roles("ann") == nil || r.status().Ended {
		t.Fatal("a notice for another enrolment key ended this edge")
	}
}

// Policy modules are named by hash and fetched once per policy change, not every pull.
func TestThePolicyModuleIsFetchedOnceAndKept(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { return r.roles("ann") != nil })
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour)), lease("L-2", time.Now().Add(time.Hour))}, nil)
	r.eventually("a second bundle is applied", func() bool { return r.status().AppliedSerial >= 2 })
	if n := r.kc.ModuleFetchCount(); n != 1 {
		t.Fatalf("the module was fetched %d times, want once", n)
	}
	if st := r.status(); st.ModuleFailures != 0 {
		t.Fatalf("%d module failures", st.ModuleFailures)
	}
}

func TestShadowModeChangesNothingAndReportsTheDisagreement(t *testing.T) {
	r := newRig(t, Shadow)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("the plan is reported", func() bool { st := r.status(); return st.PlanActions > 0 && st.NonEmptyStreak > 2 })
	if r.roles("ann") != nil {
		t.Fatal("shadow mode changed Warpgate")
	}
}

func TestARestartReappliesFromTheStoredBundle(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { return r.roles("ann") != nil })
	r.halt()
	// Someone removes ann by hand while the agent is down, and the desk is unreachable.
	ctx := context.Background()
	wgHTTP, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, PinSHA256: r.wgPin})
	wc := &warpgate.Client{Base: r.wgURL, Token: "tok", HTTP: wgHTTP}
	users, _ := wc.Users(ctx)
	for _, u := range users {
		_ = wc.DeleteUser(ctx, u.ID)
	}
	r.kc.SetFaults(true, false)
	r.start()
	r.eventually("ann is restored from the stored bundle", func() bool { return r.roles("ann") != nil })
}

// The events chain across a restart (decision 0025 point 2): the sequence goes on, the new run opens a new epoch,
// status.json reports the head, and a record removed or altered breaks the chain.
func TestTheEventsChainAcrossARestart(t *testing.T) {
	r := newRig(t, Enforce)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann's account is an event", func() bool {
		return slices.Contains(r.seen("account:edge-a/ann"), "relikey.account.created.v1")
	})
	r.halt()
	r.mu.Lock()
	before := len(r.lines)
	r.mu.Unlock()
	r.start()
	r.kc.SetLeases(nil, []string{"L-1"})
	r.eventually("ann's deletion is an event", func() bool {
		return slices.Contains(r.seen("account:edge-a/ann"), "relikey.account.deleted.v1")
	})
	r.mu.Lock()
	lines := slices.Clone(r.lines)
	r.mu.Unlock()
	head, restarts, err := events.Verify(lines, &events.Head{})
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != int64(len(lines)) || !slices.Equal(restarts, []int64{1, int64(before) + 1}) || head.Epoch != 2 {
		t.Fatalf("head %+v, restarts %v after %d lines, %d before the restart", head, restarts, len(lines), before)
	}
	r.eventually("status.json reports the head", func() bool {
		st := r.status()
		return st.EventChain != nil && *st.EventChain == head
	})
	if r.store.Chain() != head {
		t.Fatalf("the stored head %+v is not the last line's %+v", r.store.Chain(), head)
	}
	if _, _, err := events.Verify(slices.Delete(slices.Clone(lines), before, before+1), &events.Head{}); err == nil {
		t.Fatal("the chain holds without the first record after the restart")
	}
	altered := slices.Clone(lines)
	altered[0] = bytes.Replace(altered[0], []byte(`"outcome":"success"`), []byte(`"outcome":"failure"`), 1)
	if bytes.Equal(altered[0], lines[0]) {
		t.Fatal("the test did not alter the record")
	}
	if _, _, err := events.Verify(altered, &events.Head{}); err == nil {
		t.Fatal("the chain holds with an altered record")
	}
}

// AG-1: a lease for a person outside the officer's ceiling is never applied, though the
// bundle key signed it.
// A visit needs an assured edge by its ceiling and its attestation (KeyClerk
// ceiling.rego); this agent attests basic, so the edge refuses it and says so.
func TestAVisitIsRefusedOnABasicEdge(t *testing.T) {
	r := newRig(t, Enforce)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH"
	r.kc.SetVisits([]fakes.FakeVisit{{ID: "V-1", Person: "idp:ann", Username: "vera", SSHKey: key,
		Targets: []string{"plc"}, Role: "plc-operator", From: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Hour)}})
	r.eventually("the refusal is reported", func() bool {
		return slices.ContainsFunc(r.status().Drift, func(s string) bool { return strings.Contains(s, "V-1 is outside the edge's ceiling") })
	})
	if r.wg.UserExists("vera", apply.Marker) {
		t.Fatal("a visit lease was applied on a basic edge")
	}
}

func TestALeaseOutsideTheCeilingIsNotApplied(t *testing.T) {
	r := newRig(t, Enforce)
	eve := lease("L-1", time.Now().Add(time.Hour))
	eve.Person, eve.Username, eve.Email = "idp:eve", "eve", "eve@example.test"
	r.kc.SetLeases([]fakes.FakeLease{eve, lease("L-2", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann (inside) gets the role", func() bool { return r.roles("ann") != nil })
	time.Sleep(500 * time.Millisecond)
	if r.roles("eve") != nil {
		t.Fatal("a lease outside the ceiling was applied")
	}
}

func held(k *fakes.KeyClerk) int  { _, h := k.LongPolls(); return h }
func pulls(k *fakes.KeyClerk) int { p, _ := k.LongPolls(); return p }

// The agent restores the bastion settings ReliKey depends on, in enforce mode only, and says so either way (stack
// attack 2026-10-25, E1 and E4).
func TestTheAgentRestoresTheBastionHardening(t *testing.T) {
	shadow := newRig(t, Shadow)
	shadow.eventually("a few shadow ticks", func() bool { return shadow.status().Ticks >= 3 })
	if !shadow.wg.GetParameters().AllowOwnCredentialManagement {
		t.Fatal("shadow mode changed the bastion's settings")
	}
	r := newRig(t, Enforce)
	r.eventually("the stock parameters reset", func() bool {
		p := r.wg.GetParameters()
		return !p.AllowOwnCredentialManagement && !p.SSHClientAuthPassword && p.MaxAPITokenDurationSeconds != nil &&
			*p.MaxAPITokenDurationSeconds == bastion.APITokenMax
	})
	r.wg.SetParameters(warpgate.Parameters{AllowOwnCredentialManagement: true}) // an administrator turns it back on
	r.eventually("self-service turned off again", func() bool { return !r.wg.GetParameters().AllowOwnCredentialManagement })
}

// A password, one-time-password seed or certificate on a managed account is out of policy whatever its history (made
// before the agent ran, by an administrator, by the person while self-service was on): the next tick in enforce mode
// removes it and says so; shadow mode only reports it; the lease's SSO credential and an unmanaged account stay.
func TestACredentialAddedOutsideTheAgentIsRemovedOnTheNextTick(t *testing.T) {
	shadow := newRig(t, Shadow)
	shadow.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	shadow.wg.AddUser("ann", apply.Marker)
	shadow.wg.AddCredential("ann", "passwords")
	shadow.eventually("the credential is reported", func() bool {
		return strings.Contains(shadow.status().Plan, "delete-credential 1")
	})
	if len(shadow.wg.Credentials("ann")) != 1 {
		t.Fatal("shadow mode removed a credential")
	}

	r := newRig(t, Enforce)
	r.wg.AddUser("breakglass", "made by the installer")
	r.wg.AddCredential("breakglass", "passwords")
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	for _, kind := range warpgate.OtherCredentialKinds {
		r.wg.AddCredential("ann", kind)
	}
	r.eventually("every credential no lease grants is removed", func() bool { return len(r.wg.Credentials("ann")) == 0 })
	r.eventually("and each removal is an event", func() bool {
		n := 0
		for _, typ := range r.seen("account:edge-a/ann") {
			if typ == "relikey.account.credential_removed.v1" {
				n++
			}
		}
		return n == len(warpgate.OtherCredentialKinds)
	})
	if _, emails := r.wg.Snapshot(apply.Marker); !slices.Equal(emails["ann"], []string{"ann@example.test"}) {
		t.Fatalf("the lease's SSO credential went too: %v", emails["ann"])
	}
	if _, ok := r.roles("ann")["plc-operator"]; !ok {
		t.Fatal("the lease's role went too")
	}
	if len(r.wg.Credentials("breakglass")) != 1 {
		t.Fatal("an unmanaged account's credential was touched")
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// A lease can go live before the desk knows its person's address (run 8: the reconciler recorded it minutes later).
// The agent asks again, no sooner than noAddressRetry, and sets the SSO credential once the address is there.
func TestAnAddressTheDeskLearnsLaterStillReachesTheLease(t *testing.T) {
	old := noAddressRetry
	noAddressRetry = 300 * time.Millisecond
	t.Cleanup(func() { noAddressRetry = old })
	r := newRig(t, Enforce)
	r.kc.SetProtocol13(true)
	l := lease("L-1", time.Now().Add(time.Hour))
	l.Email = "" // the desk has no verified address yet
	r.kc.SetLeases([]fakes.FakeLease{l}, nil)
	r.eventually("the first fetch, answered without an address", func() bool { return r.kc.Fetches() >= 1 })
	if _, emails := r.wg.Snapshot(apply.Marker); len(emails["ann"]) != 0 {
		t.Fatalf("an SSO credential without an address: %v", emails["ann"])
	}
	l.Email = "ann@example.test" // the reconciler has read it now
	r.kc.SetLeases([]fakes.FakeLease{l}, nil)
	r.eventually("ann's SSO credential set from the later answer", func() bool {
		_, emails := r.wg.Snapshot(apply.Marker)
		return slices.Equal(emails["ann"], []string{"ann@example.test"})
	})
}

// Edge protocol 1.3: the bundle carries no address; the agent fetches it once per lease to set the SSO credential,
// keeps it in memory only (not in the state, the status or a log line), and does not strip the credential later.
func TestAProtocol13LeaseGetsItsSSOCredentialFromAFetchedAddress(t *testing.T) {
	var logs lockedBuf
	r := newRigTuned(t, func(a *Agent) {
		a.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	r.kc.SetProtocol13(true)
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann's SSO credential set from the fetched address", func() bool {
		_, emails := r.wg.Snapshot(apply.Marker)
		return slices.Equal(emails["ann"], []string{"ann@example.test"})
	})
	ticks := r.status().Ticks
	r.eventually("ten more ticks", func() bool { return r.status().Ticks >= ticks+10 })
	if _, emails := r.wg.Snapshot(apply.Marker); !slices.Equal(emails["ann"], []string{"ann@example.test"}) {
		t.Fatalf("the credential did not survive later ticks: %v", emails)
	}
	if n := r.kc.Fetches(); n != 1 {
		t.Fatalf("%d e-mail requests for one lease, want 1", n)
	}
	_ = filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("ann@example.test")) {
				t.Errorf("the address sits in %s", filepath.Base(p))
			}
		}
		return nil
	})
	if strings.Contains(logs.String(), "ann@example.test") {
		t.Error("the address reached a log line")
	}
}

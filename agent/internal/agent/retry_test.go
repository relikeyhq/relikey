// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"relikey/agent/internal/apply"
	"relikey/agent/internal/bastion"
	"relikey/agent/internal/fakes"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/warpgate"
)

// flaky is a bastion whose role list fails while fails is above zero (below zero: always), with err.
type flaky struct {
	bastion.Admin
	fails  atomic.Int64
	calls  atomic.Int64
	failed atomic.Int64
	err    error
}

func (f *flaky) Roles(ctx context.Context) ([]bastion.Role, error) {
	f.calls.Add(1)
	if n := f.fails.Load(); n < 0 || (n > 0 && f.fails.CompareAndSwap(n, n-1)) {
		f.failed.Add(1)
		return nil, f.err
	}
	return f.Admin.Roles(ctx)
}

var errReset = errors.New("read tcp: connection reset by peer")

func fastRetry(t *testing.T) {
	old := readBackoff
	readBackoff = time.Millisecond
	t.Cleanup(func() { readBackoff = old })
}

// standalone is an agent on a fake Warpgate with no leases, for observeTick alone.
func standalone(t *testing.T, err error) (*Agent, *flaky) {
	t.Helper()
	wg := fakes.NewWarpgate("tok", map[string][]string{"plc-operator": {"plc"}})
	srv, base, pin := wg.Serve()
	t.Cleanup(srv.Close)
	h, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, PinSHA256: pin})
	f := &flaky{Admin: warpgate.Bastion{C: &warpgate.Client{Base: base, Token: "tok", HTTP: h, RetryBase: time.Millisecond}},
		err: err}
	return &Agent{Bastion: f, Tick: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, f
}

func TestATransientReadIsAskedAgainWithinTheTick(t *testing.T) {
	fastRetry(t)
	a, f := standalone(t, errReset)
	f.fails.Store(1)
	o, err := a.observeTick(context.Background(), apply.Desired{})
	if err != nil || o == nil || o.Roles["plc-operator"] == "" {
		t.Fatalf("one failed read then a good one: %v, %+v", err, o)
	}
	if f.calls.Load() != 2 {
		t.Fatalf("roles read %d times, want 2", f.calls.Load())
	}
}

func TestRepeatedTransientFailuresAreBoundedAndReturned(t *testing.T) {
	fastRetry(t)
	a, f := standalone(t, errReset)
	f.fails.Store(-1)
	if _, err := a.observeTick(context.Background(), apply.Desired{}); !errors.Is(err, errReset) {
		t.Fatalf("every read fails: err %v, want the read's error", err)
	}
	if f.calls.Load() != int64(readAttempts) {
		t.Fatalf("roles read %d times, want %d", f.calls.Load(), readAttempts)
	}
}

func TestAPermanentFailureIsNotAskedAgain(t *testing.T) {
	fastRetry(t)
	for _, err := range []error{
		&warpgate.Error{Method: "GET", Path: "/roles", Status: 401, Body: "unauthorized"},
		bastion.ErrNotFound,
		context.DeadlineExceeded,
	} {
		a, f := standalone(t, err)
		f.fails.Store(-1)
		if _, got := a.observeTick(context.Background(), apply.Desired{}); got == nil {
			t.Fatalf("%v: no error", err)
		}
		if f.calls.Load() != 1 {
			t.Fatalf("%v: roles read %d times, want 1", err, f.calls.Load())
		}
	}
}

func TestTheRetryKeepsToTheTickAndTheContext(t *testing.T) {
	a, f := standalone(t, errReset)
	f.fails.Store(-1)
	a.Tick = 100 * time.Millisecond // shorter than the first wait (250 ms): no second read
	if _, err := a.observeTick(context.Background(), apply.Desired{}); err == nil || f.calls.Load() != 1 {
		t.Fatalf("a wait past the tick: err %v, %d reads, want an error after 1", err, f.calls.Load())
	}
	a.Tick = time.Minute
	f.calls.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := a.observeTick(ctx, apply.Desired{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a context ending during the wait: err %v", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond || f.calls.Load() != 1 {
		t.Fatalf("a context ending during the wait: returned after %v and %d reads", d, f.calls.Load())
	}
}

// With the whole agent: one failed read followed by a good one changes nothing and costs no tick; reads that keep
// failing change nothing until the bastion answers again (fail closed).
func TestAHiccupChangesNothingAndAnOutageFailsClosed(t *testing.T) {
	fastRetry(t)
	f := &flaky{err: errReset}
	r := newRigTuned(t, func(a *Agent) { f.Admin = a.Bastion; a.Bastion = f })

	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.eventually("the plan is applied in full", func() bool { st := r.status(); return st.Executed > 0 && st.PlanActions == 0 })
	before := r.status()
	f.fails.Store(1)
	r.eventually("the failed read is followed by two more ticks", func() bool {
		return f.failed.Load() == 1 && r.status().Ticks > before.Ticks+2
	})
	if st := r.status(); st.ObserveErrors != 0 || st.Executed != before.Executed {
		t.Fatalf("one failed read: %d observe errors, %d actions (before %d), want none", st.ObserveErrors, st.Executed,
			before.Executed)
	}
	if _, ok := r.roles("ann")["plc-operator"]; !ok {
		t.Fatal("one failed read cost ann her role")
	}

	f.fails.Store(-1)
	r.kc.SetLeases(nil, nil)
	r.eventually("the outage is reported", func() bool { return r.status().ObserveErrors >= 2 })
	if st := r.status(); st.Executed != before.Executed {
		t.Fatalf("the agent acted without reading the bastion: %d actions, before %d", st.Executed, before.Executed)
	}
	f.fails.Store(0)
	r.eventually("the ended lease is removed once the bastion answers", func() bool {
		_, ok := r.roles("ann")["plc-operator"]
		return !ok
	})
}

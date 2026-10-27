// SPDX-License-Identifier: EUPL-1.2

// Package agent is the edge agent's loop: pull and verify bundles from KeyClerk, keep
// the floors, and make Warpgate hold exactly what the live leases allow.
//
// One goroutine owns the loop (no shared mutable state). Every tick it recomputes the
// live leases from the stored, verified bundle at the trusted time, so leases end on the
// edge without asking anyone; every pull it verifies a new bundle against the floors.
// In shadow mode it computes and reports the plan and never changes the bastion: the canary.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"encoding/json/v2"

	"relikey/agent/internal/apply"
	"relikey/agent/internal/bastion"
	"relikey/agent/internal/clock"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/internal/state"
	"relikey/agent/pkg/events"
	"relikey/agent/pkg/fleetproto"
)

// Mode is enforce (apply the plan) or shadow (report it only).
type Mode string

const (
	Enforce Mode = "enforce"
	Shadow  Mode = "shadow"
)

// Agent wires the parts. All fields are set by the caller (cmd/relikey-agent).
type Agent struct {
	Pins     kcedge.Pins
	Provider string // the SSO provider name in Warpgate (decision 0010)
	Mode     Mode
	Version  string
	// Release is the bare version the fleet report carries ("v0.27.0", "dev-26734a855cd6"); Version is the display
	// string with the program, commit and Go (full-stack run 5: the display string failed the report's format).
	Release string
	Store   *state.Store
	Clerk   Clerk         // the clerk role: whatever speaks the edge protocol (decision 0023)
	Bastion bastion.Admin // the bastion role; Warpgate is the reference adapter
	Clock   clock.Clock
	Log     *slog.Logger
	Tick    time.Duration // lease ends are enforced within one tick (default 15s)
	Pull    time.Duration // pull interval (default 60s), jittered 10%: the floor between pulls
	// Wait is the long-poll hold asked of the desk (KeyClerk decision 0026, at most 55 s); 0 pulls plainly. A held
	// answer is followed by the next long-poll at once; an immediate answer or a failure by the jittered interval.
	Wait        time.Duration
	Grace       time.Duration // removals may finish this long after a shutdown signal (default 5s)
	StatusEvery int           // write status.json every N ticks (default 1)
	// The key exchange each role's link negotiated (decision 0022 A3); nil leaves it out of the status.
	ClerkTLS, BastionTLS *httpx.Group
	// Governed loads the bastion roles only leases grant, read every tick (apply.ParseGoverned); an unmanaged account
	// holding one is reported, never changed (full-stack run 2, finding 8). Nil leaves unmanaged accounts unchecked.
	Governed func() (map[string]bool, error)
	// Emit writes one monitoring event (decision 0025: CloudEvents with OCSF data, the platform's alert-event fields);
	// nil emits nothing.
	Emit func(events.Event)
	// Fleet receives the edge's signed report every pull interval (decision 0026, ReliKey's own fleet service); nil
	// sends none. It returns only an error: the fleet service is read-only towards edges (0026 point 9).
	Fleet interface {
		Send(ctx context.Context, r fleetproto.Report) error
	}
	fleetSeq     int64
	fleetLast    time.Time // monotonic: when the last report went, so a clock set back cannot stall reports
	fleetSending atomic.Bool

	rogue map[string]string // the unmanaged accounts holding governed roles last reported, and their roles
	// digest is the content digest of the last bundle pulled (kcedge.ContentDigest): an answer with the same content
	// that came at once means the desk did not hold the long-poll (over its cap, or older than KeyClerk 0026).
	digest string

	// emails are the verified addresses of live leases whose bundle carries none (edge protocol 1.3), fetched from
	// the desk and kept in memory only, for the lease's life: never in the state, the status or a log line.
	emails map[string]fetchedEmail

	st Status
}

// noAddressRetry is how long a lease the desk had no address for waits before it asks again (a variable for tests).
var noAddressRetry = time.Minute

type fetchedEmail struct {
	person, email string
	has           bool      // false: the broker holds no verified address
	tried         time.Time // monotonic: a failed fetch waits before the next (the desk allows six a minute)
	ok            bool
}

// withEmails fills in the address of each live lease whose bundle carries none, from the desk (edge protocol 1.3).
// One fetch per lease while it is live; a failure is retried no sooner than 15 s later. A lease the desk does not
// know (404) or no verified address stays without one, and the drift report says so as before; "no address" is asked
// again no sooner than noAddressRetry later, because the desk may learn the address after the lease went live (run 8:
// the reconciler recorded it minutes after, and the lease never got its SSO credential).
func (a *Agent) withEmails(ctx context.Context, leases []kcedge.Lease) []kcedge.Lease {
	if a.emails == nil {
		a.emails = map[string]fetchedEmail{}
	}
	live := map[string]bool{}
	out := slices.Clone(leases)
	for i, l := range out {
		live[l.LeaseID] = true
		if l.Email != "" {
			continue
		}
		f, seen := a.emails[l.LeaseID]
		if seen && f.person != l.Person {
			seen = false // the id now names another person: never carry an address across
		}
		if !seen || (!f.ok && time.Since(f.tried) >= 15*time.Second) || (f.ok && !f.has && time.Since(f.tried) >= noAddressRetry) {
			f = a.fetchEmail(ctx, l)
			a.emails[l.LeaseID] = f
		}
		if f.ok && f.has {
			out[i].Email = f.email
		}
	}
	for id := range a.emails {
		if !live[id] {
			delete(a.emails, id)
		}
	}
	return out
}

func (a *Agent) fetchEmail(ctx context.Context, l kcedge.Lease) fetchedEmail {
	f := fetchedEmail{person: l.Person, tried: time.Now()}
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	s, nonce, err := a.Clerk.Email(fctx, l.LeaseID)
	if err == nil {
		f.email, f.has, err = kcedge.VerifyEmail(*s, a.Pins, l.LeaseID, nonce)
	}
	if err != nil {
		a.Log.Warn("the lease's address could not be fetched", "lease", l.LeaseID, "err", err) // never the address
		return f
	}
	f.ok = true
	return f
}

// Clerk is the clerk role as the agent uses it (decision 0023): the transport of the edge protocol, published as an
// open specification (github.com/keyclerk/edge-protocol). What it returns is verified against pinned keys here, never
// trusted for arriving.
type Clerk interface {
	Pull(ctx context.Context, after int64, wait time.Duration) (keyclerk.Pulled, error)
	FetchModule(ctx context.Context, sha256hex string) ([]byte, error)
	SendReport(ctx context.Context, r keyclerk.Report) error
	EnrolmentKey() ed25519.PublicKey
	// Email fetches a lease's verified address (edge protocol 1.3): the sealed answer and the request's nonce.
	Email(ctx context.Context, leaseID string) (*kcedge.Sealed, string, error)
}

// Status is the agent's own account of itself, in status.json for the operator, the
// canary gate and the soak harness.
type Status struct {
	Version        string      `json:"version"`
	Mode           Mode        `json:"mode"`
	Edge           string      `json:"edge"`
	Started        time.Time   `json:"started"`
	Updated        time.Time   `json:"updated"`
	Ticks          int64       `json:"ticks"`
	PullsOK        int64       `json:"pulls_ok"`
	PullsFailed    int64       `json:"pulls_failed"`
	Refused        int64       `json:"bundles_refused"`
	LastRefusal    string      `json:"last_refusal,omitempty"`
	Serial         int64       `json:"serial"`
	AppliedSerial  int64       `json:"applied_serial"`
	LiveLeases     int         `json:"live_leases"`
	Leases         []LeaseView `json:"leases"`
	Plan           string      `json:"plan"`
	PlanActions    int         `json:"plan_actions"`
	NonEmptyStreak int         `json:"nonempty_streak"` // consecutive ticks with a plan left over
	MaxStreak      int         `json:"max_nonempty_streak"`
	Executed       int64       `json:"actions_executed"`
	Failures       int64       `json:"action_failures"`
	LastFailure    string      `json:"last_failure,omitempty"`
	ObserveErrors  int64       `json:"observe_errors"`
	ModuleFailures int64       `json:"module_failures"`
	ClockSkewed    bool        `json:"clock_skewed"`
	Ended          bool        `json:"ended"`
	// The key exchange group the last handshake to each peer negotiated (X25519MLKEM768 on a hybrid link).
	ClerkTLS   string   `json:"clerk_tls_group,omitempty"`
	BastionTLS string   `json:"bastion_tls_group,omitempty"`
	Drift      []string `json:"drift"`
	Goroutines int      `json:"goroutines"`
	HeapAlloc  uint64   `json:"heap_alloc"`
	HeapSys    uint64   `json:"heap_sys"`
	NumGC      uint32   `json:"num_gc"`
	OpenFDs    int      `json:"open_fds"`
}

func (a *Agent) defaults() {
	if a.Tick <= 0 {
		a.Tick = 15 * time.Second
	}
	a.Wait = min(a.Wait, keyclerk.MaxWait) // the desk's longest hold; the pull's timeout is 30 s above it
	if a.Pull <= 0 {
		a.Pull = 60 * time.Second
	}
	if a.Grace <= 0 {
		a.Grace = 5 * time.Second
	}
	if a.StatusEvery <= 0 {
		a.StatusEvery = 1
	}
	if a.Mode == "" {
		a.Mode = Enforce
	}
}

// Run loops until ctx is done. It reconciles from the stored bundle first, so a
// restart re-applies what was verified before the first pull answers.
func (a *Agent) Run(ctx context.Context) error {
	a.defaults()
	now := a.Clock.Now()
	a.st = Status{Version: a.Version, Mode: a.Mode, Edge: a.Pins.Edge, Started: now, Drift: []string{}}
	a.Log.Info("agent started", "edge", a.Pins.Edge, "mode", a.Mode, "version", a.Version)
	a.reconcile(ctx)
	a.pull(ctx)
	tick := time.NewTicker(a.Tick)
	defer tick.Stop()
	pull := time.NewTimer(a.jitter())
	if a.Wait > 0 {
		pull.Reset(0) // long-poll from the start: the first answer waits for a change
	}
	defer pull.Stop()
	asks, answers := make(chan int64), make(chan answer)
	go a.fetcher(ctx, asks, answers)
	for {
		select {
		case <-ctx.Done():
			a.Log.Info("agent stopping")
			a.writeStatus()
			return nil
		case <-tick.C:
			a.reconcile(ctx)
			a.reportToFleet(ctx)
		case <-pull.C:
			// The fetcher is idle (it is asked again only after its answer was handled), unless shutdown already
			// stopped it: a select may pick the timer over ctx.Done, so the send watches ctx too.
			select {
			case asks <- a.Store.Get().Floors.Serial:
			case <-ctx.Done():
			}
		case r := <-answers:
			changed := a.handlePull(ctx, r.got, r.err)
			if r.err == nil && a.Wait > 0 && (r.held >= max(heldMin, a.Wait/2) || changed) {
				pull.Reset(0) // held, or a change: ask again at once, the next answer waits for the next change
			} else {
				pull.Reset(a.jitter()) // an immediate answer or a failure: the interval is the floor, never a tight loop
			}
		}
	}
}

// heldMin is the floor for telling a held answer from an immediate one; an answer counts as held only after at least
// half the wait, so a slow link to a desk that does not hold never looks held.
const heldMin = 2 * time.Second

type answer struct {
	got  keyclerk.Pulled
	err  error
	held time.Duration
}

// fetcher runs the pulls off the loop: one at a time, each after the loop asked with the serial it holds.
func (a *Agent) fetcher(ctx context.Context, asks <-chan int64, answers chan<- answer) {
	for {
		var after int64
		select {
		case <-ctx.Done():
			return
		case after = <-asks:
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second+a.Wait)
		start := time.Now()
		got, err := a.Clerk.Pull(pctx, after, a.Wait)
		cancel()
		select {
		case answers <- answer{got, err, time.Since(start)}:
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) jitter() time.Duration {
	j := int64(a.Pull) / 10
	return a.Pull - time.Duration(j) + time.Duration(rand.Int64N(2*j+1))
}

// fetchModules keeps every policy module the verified bundle names, by hash, once per
// policy change. The ceiling decision runs in the Go port of ceiling.rego until the
// in-process module runtime lands, so a module that cannot be fetched is reported and
// retried at the next pull; it never blocks the bundle.
func (a *Agent) fetchModules(ctx context.Context, b *kcedge.Sealed) {
	refs, err := kcedge.ModuleRefs(*b, a.Pins)
	if err != nil {
		return
	}
	for name, sum := range refs {
		if a.Store.HasModule(sum) {
			continue
		}
		raw, err := a.Clerk.FetchModule(ctx, sum)
		if err == nil {
			err = a.Store.WriteModule(sum, raw)
		}
		if err != nil {
			a.st.ModuleFailures++
			a.Log.Warn("policy module not fetched: retried at the next pull", "module", name, "sha256", sum, "err", err)
			continue
		}
		a.Log.Info("policy module kept", "module", name, "sha256", sum, "bytes", len(raw))
	}
}

// pull asks the desk for the newest bundle and keeps it when it verifies.
func (a *Agent) pull(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	got, err := a.Clerk.Pull(pctx, 0, 0)
	a.handlePull(ctx, got, err)
}

// handlePull keeps a pulled bundle when it verifies, or acts on an ended notice. It reports whether the bundle's
// content differs from the last one pulled.
func (a *Agent) handlePull(ctx context.Context, got keyclerk.Pulled, err error) (changed bool) {
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err != nil {
		a.st.PullsFailed++
		a.Log.Warn("pull failed: the desk is unreachable or refused; leases already verified stay in force until they end",
			"err", err)
		return
	}
	a.st.PullsOK++
	rec := a.Store.Get()
	if got.Ended != nil {
		reason, err := kcedge.VerifyEnded(*got.Ended, a.Pins, hex.EncodeToString(a.Clerk.EnrolmentKey()))
		if err != nil {
			a.refused("an ended notice that does not verify: " + err.Error())
			return
		}
		if !rec.Ended {
			rec.Ended = true
			if err := a.Store.Save(rec); err != nil {
				a.Log.Error("cannot record the end of the edge", "err", err)
				return
			}
			a.Log.Warn("the desk ended this edge: removing all access", "reason", reason)
			a.emitEnded(reason)
		}
		a.reconcile(ctx)
		return
	}
	if rec.Ended {
		return // an ended edge never takes a bundle again (re-enrol to use it)
	}
	issued, serial, ierr := kcedge.Issued(*got.Bundle, a.Pins)
	if ierr == nil && serial == rec.Floors.Serial {
		a.report(ctx, rec.AppliedSerial)
		return // the same bundle again: nothing new
	}
	now, _ := clock.Trusted(a.Clock, parseWall(rec.WallAtVerify), a.bootAtVerify(rec), kcedge.Skew)
	applied, err := kcedge.VerifyBundle(*got.Bundle, a.Pins, rec.Floors, now, kcedge.CeilingPolicyGo)
	if err != nil {
		a.refused(err.Error())
		a.report(ctx, rec.AppliedSerial)
		return
	}
	rec.Floors, rec.Bundle = applied.State, got.Bundle
	rec.BootID, rec.BootAtVerify, rec.WallAtVerify = a.Clock.BootID(), int64(a.Clock.Boot()), formatWall(now)
	// Floors and the bundle are stored before anything is applied: a crash after this
	// re-applies from the stored bundle, never leaving a refused serial with stale state.
	if err := a.Store.Save(rec); err != nil {
		a.Log.Error("cannot store the verified bundle: not applied", "err", err)
		return
	}
	a.Log.Info("bundle verified", "serial", serial, "issued", issued, "live_leases", len(applied.Leases))
	// Only a verified, stored bundle can count as a change: a refused or replayed one never earns an immediate
	// re-poll (second red team of 0025: a desk alternating bad answers would otherwise drive a tight loop).
	if d, derr := kcedge.ContentDigest(*got.Bundle, a.Pins); derr == nil {
		changed, a.digest = d != a.digest, d
	}
	a.fetchModules(pctx, got.Bundle)
	a.reconcile(ctx)
	a.report(ctx, a.Store.Get().AppliedSerial)
	return changed
}

func (a *Agent) refused(why string) {
	a.st.Refused++
	a.st.LastRefusal = why
	a.Log.Warn("bundle refused; the edge keeps what it holds", "why", why)
	a.emitRefused(why)
}

func (a *Agent) bootAtVerify(rec state.Record) time.Duration {
	if rec.BootID == "" || rec.BootID != a.Clock.BootID() || rec.BootAtVerify <= 0 {
		return -1
	}
	return time.Duration(rec.BootAtVerify)
}

// live is what the stored bundle allows at the trusted moment, with the reasons when
// nothing is live.
func (a *Agent) live(rec state.Record) (live, time.Time, []string) {
	now, skewed := clock.Trusted(a.Clock, parseWall(rec.WallAtVerify), a.bootAtVerify(rec), kcedge.Skew)
	switch {
	case rec.Ended:
		return live{}, now, []string{"the desk ended this edge: no access"}
	case rec.Bundle == nil:
		return live{}, now, []string{"no verified bundle yet: no access"}
	case rec.BootID != "" && a.Clock.BootID() != "" && rec.BootID != a.Clock.BootID():
		// Elapsed time across a reboot is unknown on a basic edge (no TPM clock).
		return live{}, now, []string{"rebooted since the last verified bundle: no lease is live until a fresh bundle verifies"}
	}
	a.st.ClockSkewed = skewed
	var drift []string
	if skewed {
		drift = append(drift, "the wall clock and the boot clock disagree by more than 5 minutes: "+
			"the later time is used, so leases end early rather than late")
	}
	applied, err := kcedge.LiveAt(*rec.Bundle, a.Pins, now, kcedge.CeilingPolicyGo)
	if err != nil {
		return live{}, now, append(drift, "the stored bundle no longer verifies: no access ("+err.Error()+")")
	}
	for _, id := range applied.RefusedByCeiling {
		drift = append(drift, "lease "+id+" is outside the edge's ceiling: not applied")
	}
	return live{applied.Leases, applied.VisitLeases, applied.GovernedRoles}, now, drift
}

// live is what the stored bundle allows now: leases and visit leases, and the roles the clerk governs here.
type live struct {
	leases   []kcedge.Lease
	visits   []kcedge.VisitLease
	governed *[]string
}

// observe reads Warpgate, with the targets of the roles visit leases grant and the governed roles unmanaged accounts hold.
func (a *Agent) observe(ctx context.Context, desired apply.Desired) (*apply.Observed, error) {
	observed, err := apply.Observe(ctx, a.Bastion)
	if err == nil {
		err = observed.ReadRoleTargets(ctx, a.Bastion, desired)
	}
	if err != nil {
		return observed, err
	}
	// The governed roles are the union of the edge's own file and the clerk's signed catalogue: neither source can be
	// assumed present, and each only adds roles to report (finding 8; KeyClerk decision 0025).
	governed, sources := map[string]bool{}, 0
	if a.Governed != nil {
		if g, gerr := a.Governed(); gerr != nil {
			observed.Notes = append(observed.Notes, gerr.Error()+": the edge's governed roles were not read this tick")
		} else {
			maps.Copy(governed, g)
			sources++
		}
	}
	if desired.Governed != nil {
		for _, r := range *desired.Governed {
			governed[r] = true
		}
		sources++
	}
	if sources > 0 {
		err = observed.ReadUnmanagedGrants(ctx, a.Bastion, governed, desired.Now)
		// The edge's file failed but the bundle carried a catalogue: the set is incomplete, so nothing is resolved.
		observed.RoguePartial = a.Governed != nil && sources == 1 && desired.Governed != nil
	}
	return observed, err
}

// harden checks the bastion settings ReliKey depends on and, in enforce mode, restores them; either way the drift
// report says what was found (stack attack 2026-10-25, E1 and E4).
func (a *Agent) harden(ctx context.Context, o *apply.Observed) {
	h, ok := a.Bastion.(bastion.Hardener)
	if !ok {
		return
	}
	cur, err := h.Hardening(ctx)
	if err != nil {
		o.Notes = append(o.Notes, "the bastion's settings could not be read this tick: "+err.Error())
		return
	}
	weak := cur.Weaknesses()
	switch {
	case len(weak) == 0:
	case a.Mode != Enforce:
		o.Notes = append(o.Notes, "the bastion allows "+strings.Join(weak, ", ")+": not changed in shadow mode")
	default:
		if err := h.Harden(ctx); err != nil {
			o.Notes = append(o.Notes, "the bastion allows "+strings.Join(weak, ", ")+" and could not be reset: "+err.Error())
		} else {
			o.Notes = append(o.Notes, "the bastion allowed "+strings.Join(weak, ", ")+": reset")
		}
	}
}

// reconcile makes Warpgate match the live leases (or, in shadow mode, says how).
func (a *Agent) reconcile(ctx context.Context) {
	a.st.Ticks++
	rec := a.Store.Get()
	l, now, why := a.live(rec)
	l.leases = a.withEmails(ctx, l.leases)
	leases := l.leases
	desired := apply.FromLive(l.leases, l.visits)
	desired.Now, desired.Governed = now, l.governed
	octx, cancel := context.WithTimeout(ctx, 30*time.Second)
	observed, err := a.observe(octx, desired)
	cancel()
	if err != nil {
		a.st.ObserveErrors++
		a.Log.Warn("cannot read Warpgate; nothing changed this tick", "err", err)
		a.finishTick(nil, why)
		return
	}
	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	a.harden(hctx, observed)
	hcancel()
	plan := apply.Compute(desired, observed, a.Provider)
	a.emitRogue(observed)
	a.st.LiveLeases, a.st.Leases = len(leases), leaseViews(leases)
	if a.Mode == Enforce {
		failed := 0
		if len(plan.Actions) > 0 {
			// No grant starts after a shutdown signal or the plan's deadline (a hanging
			// Warpgate must not hold the loop, AG-15); removals finish within the grace.
			ectx, cancel := context.WithTimeout(ctx, 60*time.Second)
			res := apply.Execute(ectx, a.Bastion, a.Provider, plan, a.Grace)
			cancel()
			a.st.Executed += int64(res.Done)
			a.st.Failures += int64(len(res.Failed))
			failed = len(res.Failed)
			if failed > 0 {
				a.st.LastFailure = res.Failed[0]
				a.Log.Warn("some actions failed; the next tick plans again", "failed", failed, "first", res.Failed[0])
			}
			a.Log.Info("applied", "plan", plan.Summary(), "done", res.Done)
			a.emitApplied(res.Applied)
		}
		if failed == 0 && rec.Bundle != nil && !rec.Ended {
			_, serial, _ := kcedge.Issued(*rec.Bundle, a.Pins)
			if serial > rec.AppliedSerial {
				rec.AppliedSerial = serial
				if err := a.Store.Save(rec); err != nil {
					a.Log.Error("cannot record the applied serial", "err", err)
				}
			}
		}
	} else if len(plan.Actions) > 0 {
		a.Log.Info("shadow: would apply", "plan", plan.Summary())
	}
	a.finishTick(&plan, why)
}

func (a *Agent) finishTick(plan *apply.Plan, why []string) {
	if plan != nil {
		a.st.Plan, a.st.PlanActions = plan.Summary(), len(plan.Actions)
		// Enforce: a plan left over after executing would show next tick. Shadow: the
		// plan is the disagreement with whoever enforces.
		if len(plan.Actions) > 0 {
			a.st.NonEmptyStreak++
		} else {
			a.st.NonEmptyStreak = 0
		}
		a.st.MaxStreak = max(a.st.MaxStreak, a.st.NonEmptyStreak)
		why = append(why, plan.Drift...)
	}
	slices.Sort(why)
	a.st.Drift = slices.Compact(why)
	rec := a.Store.Get()
	a.st.Serial, a.st.AppliedSerial, a.st.Ended = rec.Floors.Serial, rec.AppliedSerial, rec.Ended
	a.st.ClerkTLS, a.st.BastionTLS = a.ClerkTLS.String(), a.BastionTLS.String()
	if a.st.Ticks%int64(a.StatusEvery) == 0 {
		a.writeStatus()
	}
}

func (a *Agent) writeStatus() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	a.st.Updated, a.st.Goroutines = a.Clock.Now(), runtime.NumGoroutine()
	a.st.HeapAlloc, a.st.HeapSys, a.st.NumGC, a.st.OpenFDs = ms.HeapAlloc, ms.HeapSys, ms.NumGC, openFDs()
	b, err := json.Marshal(a.st)
	if err == nil {
		err = a.Store.WriteStatus("status.json", b)
	}
	if err == nil {
		if b, err = RenderPage(a.st, a.st.Updated); err == nil {
			err = a.Store.WriteStatus("status.html", b)
		}
	}
	if err == nil {
		err = a.Store.WriteStatus("metrics.prom", Metrics(a.st, a.st.Health(a.st.Updated, 2, 2*time.Minute)))
	}
	if err != nil {
		a.Log.Warn("cannot write the status files", "err", err)
	}
}

func (a *Agent) report(ctx context.Context, applied int64) {
	drift := a.st.Drift
	if len(drift) > 50 {
		drift = drift[:50]
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err := a.Clerk.SendReport(rctx, keyclerk.Report{AppliedSerial: applied, Drift: drift,
		Attestation: keyclerk.Attestation{Profile: kcedge.AttestedProfile, AgentVersion: a.Version, Mode: string(a.Mode)}})
	if err != nil && !errors.Is(err, context.Canceled) {
		a.Log.Warn("report not delivered; sent again after the next pull", "err", err)
	}
}

// Once runs a single reconcile and returns the plan (the plan subcommand; shadow).
func (a *Agent) Once(ctx context.Context) (apply.Plan, error) {
	a.defaults()
	l, now, why := a.live(a.Store.Get())
	desired := apply.FromLive(l.leases, l.visits)
	desired.Now, desired.Governed = now, l.governed
	observed, err := a.observe(ctx, desired)
	if err != nil {
		return apply.Plan{}, fmt.Errorf("reading the bastion: %w", err)
	}
	p := apply.Compute(desired, observed, a.Provider)
	p.Drift = append(why, p.Drift...)
	return p, nil
}

func parseWall(s string) time.Time {
	t, _ := kcedge.ParseTime(s)
	return t
}

func formatWall(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// reportToFleet sends the fleet service a signed report, at most once per pull interval and one at a time, off the
// loop so a slow or absent fleet service never holds a tick. The sequence comes from the trusted clock, so it still
// rises after a restart.
func (a *Agent) reportToFleet(ctx context.Context) {
	if a.Fleet == nil {
		return
	}
	// The interval is measured on the monotonic clock; the sequence only guards against replay (red team of
	// 2026-10-25: gating on the clock-based sequence stalled reports for as long as the clock was set back).
	if !a.fleetLast.IsZero() && time.Since(a.fleetLast) < a.Pull {
		return
	}
	now := a.Clock.Now()
	seq := max(now.UnixMilli(), a.fleetSeq+1)
	if !a.fleetSending.CompareAndSwap(false, true) {
		return
	}
	a.fleetSeq, a.fleetLast = seq, time.Now()
	st := a.st
	r := fleetproto.Report{Edge: a.Pins.Edge, Seq: seq, At: now.UTC(), Release: a.Release, Mode: string(st.Mode),
		Profile: kcedge.AttestedProfile, Serial: st.Serial, AppliedSerial: st.AppliedSerial, LiveLeases: st.LiveLeases,
		DriftCodes: fleetproto.DriftCodes(st.Drift), ClerkTLS: st.ClerkTLS, BastionTLS: st.BastionTLS}
	go func() {
		defer a.fleetSending.Store(false)
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := a.Fleet.Send(sctx, r); err != nil {
			a.Log.Warn("fleet report not delivered; sent again next interval", "err", err)
		}
	}()
}

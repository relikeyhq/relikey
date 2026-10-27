// SPDX-License-Identifier: EUPL-1.2

// Command relikey-soak runs the real relikey-agent binary against the fake KeyClerk and
// Warpgate for a long time, with lease churn and injected faults, and checks two things
// all along: no access outlives its lease (safety), and live leases get applied
// (liveness); it samples the agent's memory, goroutines and file descriptors to find
// leaks. It is a test tool, never shipped (build.py release builds relikey-agent only).
//
//	relikey-soak -agent ./relikey-agent -minutes 40 -out soak/
//
// The fake Warpgate ignores expiry (a Warpgate whose clock was set back), so every lease
// end is the agent's own doing.
package main

import (
	"crypto/ed25519"
	"encoding/csv"
	"encoding/hex"
	"encoding/json/v2"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"relikey/agent/internal/agent"
	"relikey/agent/internal/apply"
	"relikey/agent/internal/fakes"
)

const (
	users = 20
	tick  = time.Second
	pull  = 2 * time.Second
	// margin is how long access may outlive its lease: a pull to learn a revocation, a
	// tick to act, retries under faults, and the harness's own sampling.
	margin = 12 * time.Second
	// churnEvery is how often the harness changes leases and faults.
	churnEvery = 3 * time.Second
)

var targets = map[string][]string{"plc-operator": {"target-plc"}, "hmi-viewer": {"target-hmi"}, "eng-admin": {"target-plc", "target-hmi"}}

// grant is one lease the desk ever issued, with when it stopped being granted.
type grant struct {
	user, role                string
	granted, until, withdrawn time.Time // withdrawn: revoked or dropped from the desk's set
}

// window is a fault: desk (the desk cannot deliver bundles) or warpgate (nothing can be changed).
type window struct {
	desk       bool
	start, end time.Time
}

type harness struct {
	windows   []window
	mu        sync.Mutex
	kc        *fakes.KeyClerk
	wg        *fakes.Warpgate
	history   []*grant
	current   map[string]*grant // lease id -> grant
	seq       int
	faultTill time.Time
	faults    map[string]int
	safety    []string
	liveness  int
	checks    int
}

func main() {
	agentBin := flag.String("agent", "./relikey-agent", "the agent binary to soak")
	minutes := flag.Float64("minutes", 30, "how long")
	out := flag.String("out", "soak", "output directory (samples.csv, summary.json, agent.log)")
	seed := flag.Uint64("seed", uint64(time.Now().UnixNano()), "random seed (printed, to replay a run)")
	flag.Parse()
	rng := rand.New(rand.NewPCG(*seed, 7))
	must(os.MkdirAll(*out, 0o700))
	dir, _ := filepath.Abs(*out)
	stateDir := filepath.Join(dir, "state")
	_ = os.RemoveAll(stateDir)
	must(os.Mkdir(stateDir, 0o700))

	enrol := fakes.Key(9)
	h := &harness{current: map[string]*grant{}, faults: map[string]int{}}
	persons, tgts := []string{}, []string{"plc", "hmi"}
	for i := range users {
		persons = append(persons, fmt.Sprintf("idp:u%02d", i))
	}
	h.kc = fakes.NewKeyClerk("edge-soak", enrol.Public().(ed25519.PublicKey), persons, tgts)
	h.wg = fakes.NewWarpgate("soak-token", targets)
	h.wg.IgnoreExpiry = true
	h.wg.AddUser("breakglass", "installer account, never touched by the agent")
	kcSrv, kcURL, kcPin := h.kc.Serve()
	defer kcSrv.Close()
	wgSrv, wgURL, wgPin := h.wg.Serve()
	defer wgSrv.Close()

	keyFile, tokFile := filepath.Join(dir, "enrolment.key"), filepath.Join(dir, "warpgate.token")
	must(os.WriteFile(keyFile, []byte(hex.EncodeToString(enrol.Seed())+"\n"), 0o600))
	must(os.WriteFile(tokFile, []byte("soak-token\n"), 0o600))
	pins := h.kc.Pins()
	cfg := map[string]any{"edge": "edge-soak", "mode": "enforce", "state_dir": stateDir, "lab": true,
		"enrolment_key_file": keyFile, "pins": map[string]any{"bundle_key": pins.BundleKey, "officer_key": pins.OfficerKey},
		"clerk":        map[string]any{"url": kcURL, "pin_sha256": kcPin},
		"bastion":      map[string]any{"kind": "warpgate", "url": wgURL, "token_file": tokFile, "pin_sha256": wgPin, "sso_provider": "keycloak"},
		"tick_seconds": int(tick / time.Second), "pull_seconds": int(pull / time.Second), "grace_seconds": 3}
	cfgFile := filepath.Join(dir, "agent.json")
	b, _ := json.Marshal(cfg)
	must(os.WriteFile(cfgFile, b, 0o600))

	logf, err := os.Create(filepath.Join(dir, "agent.log"))
	must(err)
	defer logf.Close()
	cmd := exec.Command(*agentBin, "run", "-config", cfgFile)
	cmd.Stdout, cmd.Stderr = logf, logf
	must(cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	log.Printf("soak: seed %d, %v minutes, agent pid %d", *seed, *minutes, cmd.Process.Pid)

	samples, err := os.Create(filepath.Join(dir, "samples.csv"))
	must(err)
	defer samples.Close()
	cw := csv.NewWriter(samples)
	_ = cw.Write([]string{"elapsed_s", "rss_kb", "fds", "goroutines", "heap_alloc", "heap_sys", "num_gc", "ticks",
		"pulls_ok", "pulls_failed", "refused", "executed", "failures", "managed_users", "open_sessions"})

	start := time.Now()
	end := start.Add(time.Duration(*minutes * float64(time.Minute)))
	churn, check, sample := time.NewTicker(churnEvery), time.NewTicker(time.Second), time.NewTicker(10*time.Second)
	defer churn.Stop()
	defer check.Stop()
	defer sample.Stop()
	var exitErr error
loop:
	for time.Now().Before(end) {
		select {
		case exitErr = <-exited:
			break loop
		case <-churn.C:
			h.churn(rng)
		case <-check.C:
			h.check()
		case <-sample.C:
			h.sample(cw, cmd.Process.Pid, stateDir, start)
		}
	}
	if exitErr == nil {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case exitErr = <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			exitErr = fmt.Errorf("the agent did not stop within 10s of SIGINT")
		}
	} else {
		exitErr = fmt.Errorf("the agent exited during the soak: %v", exitErr)
	}
	cw.Flush()
	ok := h.summary(dir, *seed, time.Since(start), exitErr)
	if !ok {
		os.Exit(1)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// churn changes the desk's lease set and, now and then, injects a fault.
func (h *harness) churn(rng *rand.Rand) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	// Drop some leases (withdrawn: the next bundle no longer has them), revoke others.
	revoked := []string{}
	for id, g := range h.current {
		switch r := rng.Float64(); {
		case r < 0.10:
			g.withdrawn = now
			delete(h.current, id)
		case r < 0.15:
			g.withdrawn = now
			revoked = append(revoked, id)
			delete(h.current, id)
		case !g.until.After(now):
			delete(h.current, id)
		}
	}
	for range rng.IntN(4) {
		h.seq++
		u := rng.IntN(users)
		roles := slices.Sorted(func(yield func(string) bool) {
			for r := range targets {
				if !yield(r) {
					return
				}
			}
		})
		g := &grant{user: fmt.Sprintf("u%02d", u), role: roles[rng.IntN(len(roles))], granted: now,
			until: now.Add(time.Duration(5+rng.IntN(85)) * time.Second).Truncate(time.Second)}
		h.history = append(h.history, g)
		h.current[fmt.Sprintf("L-%d", h.seq)] = g
	}
	var leases []fakes.FakeLease
	for id, g := range h.current {
		leases = append(leases, fakes.FakeLease{ID: id, Person: "idp:" + g.user, Username: g.user,
			Email: g.user + "@example.test", Target: "plc", Role: g.role, Class: "low",
			From: now.Add(-time.Minute), Until: g.until})
	}
	h.kc.SetLeases(leases, revoked)

	// Sessions: people sign in to targets their roles reach (as Warpgate admits).
	view, _ := h.wg.Snapshot(apply.Marker)
	for u, roles := range view {
		for role := range roles {
			if rng.Float64() < 0.2 {
				t := targets[role][rng.IntN(len(targets[role]))]
				_, _ = h.wg.OpenSession(u, t)
			}
		}
	}
	// Faults, one at a time, 8 to 25 seconds each.
	if now.After(h.faultTill) {
		h.kc.SetFaults(false, false)
		h.wg.SetFaults(false, 0)
		if rng.Float64() < 0.15 {
			h.faultTill = now.Add(time.Duration(8+rng.IntN(18)) * time.Second)
			kind := rng.IntN(4)
			h.windows = append(h.windows, window{desk: kind < 2, start: now, end: h.faultTill})
			switch kind {
			case 0:
				h.kc.SetFaults(true, false)
				h.faults["desk down"]++
			case 1:
				h.kc.SetFaults(false, true)
				h.faults["desk replays the previous bundle"]++
			case 2:
				h.wg.SetFaults(false, 0.3)
				h.faults["warpgate 30% errors"]++
			case 3:
				h.wg.SetFaults(true, 0)
				h.faults["warpgate down"]++
			}
		}
	}
}

// deadline is when access from a grant must be gone. A lease's until is the agent's
// alone to enforce, desk or no desk; a withdrawal can only arrive once the desk delivers
// again; and nothing can be removed while Warpgate is failing, so a deadline that falls
// in a Warpgate fault moves to the fault's end.
func (h *harness) deadline(g *grant) time.Time {
	end := g.until
	if !g.withdrawn.IsZero() && g.withdrawn.Before(end) {
		// A withdrawal reaches the edge at the first pull after the desk delivers again;
		// faults started in the same churn step chain, so extend until nothing changes.
		w := extend(g.withdrawn, h.windows, true)
		if w.Before(end) {
			end = w
		}
	}
	return extend(end, h.windows, false).Add(margin)
}

// extend moves t to the end of every fault window of the kind that covers it (allowing
// for one churn step and one pull between adjacent windows), until it stops moving.
func extend(t time.Time, ws []window, desk bool) time.Time {
	for moved := true; moved; {
		moved = false
		for _, f := range ws {
			if f.desk == desk && !t.Before(f.start.Add(-churnEvery-pull)) && t.Before(f.end) {
				t, moved = f.end, true
			}
		}
	}
	return t
}

// justified: some grant for this user and role still counts at t.
func (h *harness) justified(user, role string, t time.Time) bool {
	for _, g := range h.history {
		if g.user == user && g.role == role && t.Before(h.deadline(g)) {
			return true
		}
	}
	return false
}

func (h *harness) check() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks++
	now := time.Now()
	view, _ := h.wg.Snapshot(apply.Marker)
	for u, roles := range view {
		for role := range roles {
			if !h.justified(u, role, now) {
				h.safety = append(h.safety, fmt.Sprintf("%s: %s still holds %s with no lease for %v", now.Format(time.TimeOnly), u, role, margin))
			}
		}
	}
	for id, us := range h.wg.Sessions() {
		reach := false
		for role, ts := range targets {
			if slices.Contains(ts, us[1]) && h.justified(us[0], role, now) {
				reach = true
			}
		}
		if !reach {
			h.safety = append(h.safety, fmt.Sprintf("%s: session %s of %s on %s outlived every lease reaching it",
				now.Format(time.TimeOnly), id, us[0], us[1]))
		}
	}
	if !h.wg.UserExists("breakglass", "installer account, never touched by the agent") {
		h.safety = append(h.safety, now.Format(time.TimeOnly)+": the unmanaged break-glass user was touched")
	}
	// Liveness, only when no fault was active within the margin.
	if now.After(h.faultTill.Add(margin)) {
		// A lease in the desk's set for longer than the margin, with time left, must be held.
		for _, g := range h.current {
			if g.granted.Before(now.Add(-margin)) && g.until.After(now.Add(2*time.Second)) {
				if _, ok := view[g.user][g.role]; !ok {
					h.liveness++
				}
			}
		}
	}
}

func (h *harness) sample(cw *csv.Writer, pid int, stateDir string, start time.Time) {
	var st agent.Status
	if b, err := os.ReadFile(filepath.Join(stateDir, "status.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	view, _ := h.wg.Snapshot(apply.Marker)
	_ = cw.Write([]string{strconv.Itoa(int(time.Since(start).Seconds())), strconv.Itoa(rssKB(pid)), strconv.Itoa(st.OpenFDs), // the agent is not dumpable: /proc/<pid>/fd is closed to us
		strconv.Itoa(st.Goroutines), strconv.FormatUint(st.HeapAlloc, 10), strconv.FormatUint(st.HeapSys, 10),
		strconv.Itoa(int(st.NumGC)), strconv.FormatInt(st.Ticks, 10), strconv.FormatInt(st.PullsOK, 10),
		strconv.FormatInt(st.PullsFailed, 10), strconv.FormatInt(st.Refused, 10), strconv.FormatInt(st.Executed, 10),
		strconv.FormatInt(st.Failures, 10), strconv.Itoa(len(view)), strconv.Itoa(len(h.wg.Sessions()))})
	cw.Flush()
}

func rssKB(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return -1
}

// summary judges the run: safety violations fail it; resource growth between the
// second quarter and the last quarter beyond the thresholds fails it.
func (h *harness) summary(dir string, seed uint64, took time.Duration, exitErr error) bool {
	f, _ := os.Open(filepath.Join(dir, "samples.csv"))
	rows, _ := csv.NewReader(f).ReadAll()
	f.Close()
	col := func(name string) []float64 {
		i := slices.Index(rows[0], name)
		out := []float64{}
		for _, r := range rows[1:] {
			v, _ := strconv.ParseFloat(r[i], 64)
			out = append(out, v)
		}
		return out
	}
	mean := func(xs []float64) float64 {
		if len(xs) == 0 {
			return 0
		}
		s := 0.0
		for _, x := range xs {
			s += x
		}
		return s / float64(len(xs))
	}
	growth := map[string]float64{}
	verdict := []string{}
	for _, c := range []string{"rss_kb", "fds", "goroutines", "heap_alloc"} {
		xs := col(c)
		n := len(xs)
		if n < 8 {
			continue
		}
		early, late := mean(xs[n/4:n/2]), mean(xs[3*n/4:])
		g := 0.0
		if early > 0 {
			g = (late - early) / early
		}
		growth[c] = g
		limit := map[string]float64{"rss_kb": 0.25, "fds": 0.5, "goroutines": 0.5, "heap_alloc": 0.5}[c]
		if g > limit {
			verdict = append(verdict, fmt.Sprintf("%s grew %.0f%% from the second to the last quarter (limit %.0f%%)", c, 100*g, 100*limit))
		}
	}
	maxOf := func(c string) float64 { return slices.Max(append(col(c), 0)) }
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.safety) > 0 {
		verdict = append(verdict, fmt.Sprintf("%d safety violations", len(h.safety)))
	}
	if exitErr != nil {
		verdict = append(verdict, exitErr.Error())
	}
	pulls, refusedReq := h.kc.Counts()
	wgReq, wgFailed := h.wg.Counts()
	sum := map[string]any{
		"seed": seed, "minutes": took.Minutes(), "pass": len(verdict) == 0, "verdict": verdict,
		"grants_issued": len(h.history), "checks": h.checks, "safety_violations": len(h.safety),
		"first_violations": h.safety[:min(len(h.safety), 20)], "liveness_misses": h.liveness, "faults": h.faults,
		"desk_pulls": pulls, "desk_refused_requests": refusedReq, "warpgate_requests": wgReq, "warpgate_injected_errors": wgFailed,
		"growth_q2_to_q4": growth, "max_rss_kb": maxOf("rss_kb"), "max_fds": maxOf("fds"), "max_goroutines": maxOf("goroutines"),
		"max_heap_alloc": maxOf("heap_alloc"), "samples": len(rows) - 1, "agent_stop": fmt.Sprint(exitErr),
		"fault_windows": windowsJSON(h.windows),
	}
	b, _ := json.Marshal(sum, json.Deterministic(true))
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), b, 0o600)
	fmt.Println(string(b))
	return len(verdict) == 0
}

func windowsJSON(ws []window) []map[string]string {
	out := []map[string]string{}
	for _, w := range ws {
		kind := "warpgate"
		if w.desk {
			kind = "desk"
		}
		out = append(out, map[string]string{"kind": kind, "start": w.start.Format(time.TimeOnly), "end": w.end.Format(time.TimeOnly)})
	}
	return out
}

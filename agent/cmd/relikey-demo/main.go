// SPDX-License-Identifier: EUPL-1.2

// Command relikey-demo runs the real edge agent loop against stand-ins for KeyClerk's edge routes, Warpgate's admin
// API and the identity broker, and plays a scripted story on a local page: a person signs in, a lease is granted,
// the account appears on the bastion, a session runs, the lease is revoked and the access goes, and a lease still
// ends on time while the desk cannot be reached.
//
//	go run ./cmd/relikey-demo             the story, with the page opened in a browser
//	go run ./cmd/relikey-demo -headless   the story only, one JSON line per step; exit 1 if a step does not happen
//
// It is a demo, never part of a release (build.py release builds relikey-agent only): every key is generated at
// start, every service listens on loopback, the state lives in a temporary directory that is removed on exit, and
// every screen says it is a demo. The stand-ins are the ones the agent's tests use (internal/fakes).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"sync"
	"time"

	"relikey/agent/internal/agent"
	"relikey/agent/internal/apply"
	"relikey/agent/internal/clock"
	"relikey/agent/internal/fakes"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/internal/state"
	"relikey/agent/internal/warpgate"
)

//go:embed page.html
var page []byte

// pageJS polls the story and renders it; a file of its own, so the page's policy can forbid inline script.
//
//go:embed page.js
var pageJS []byte

const (
	edge     = "edge-demo"
	provider = "demo-broker" // the bastion's SSO provider name for the stand-in broker
	target   = "plc"
	role     = "plc-operator"
	// stepWait bounds every wait for the agent; the agent ticks every 200 ms, so a step takes well under a second.
	stepWait = 20 * time.Second
)

// Step is one event of the story, as the page and the headless output show it.
type Step struct {
	N      int       `json:"n"`
	Key    string    `json:"key"`
	Title  string    `json:"title"`
	Detail string    `json:"detail"`
	At     time.Time `json:"at"`
}

// Options tune a run; the zero value is a headless run at full speed.
type Options struct {
	Pace time.Duration // a pause after each step, so a person can follow on the page
	Out  io.Writer     // one JSON line per step; nil writes none
}

// Story is the state the page reads while the scenario runs.
type Story struct {
	mu    sync.Mutex
	steps []Step
	done  bool
	err   string
	out   io.Writer
	wg    *fakes.Warpgate
}

func (s *Story) add(key, title, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Step{N: len(s.steps) + 1, Key: key, Title: title, Detail: detail, At: time.Now().UTC()}
	s.steps = append(s.steps, st)
	if s.out != nil {
		b, _ := json.Marshal(st)
		fmt.Fprintln(s.out, string(b))
	}
}

// Steps returns the steps so far.
func (s *Story) Steps() []Step {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.steps)
}

func (s *Story) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	if err != nil {
		s.err = err.Error()
	}
}

type bastionView struct {
	Accounts map[string][]string `json:"accounts"` // managed account -> roles
	Sessions [][2]string         `json:"sessions"` // username, target
}

func (s *Story) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'")
		_, _ = rw.Write(page)
	})
	mux.HandleFunc("GET /page.js", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = rw.Write(pageJS)
	})
	mux.HandleFunc("GET /api/story", func(rw http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		out := map[string]any{"steps": slices.Clone(s.steps), "done": s.done, "error": s.err}
		s.mu.Unlock()
		v := bastionView{Accounts: map[string][]string{}, Sessions: [][2]string{}}
		if s.wg != nil {
			view, _ := s.wg.Snapshot(apply.Marker)
			for u, roles := range view {
				v.Accounts[u] = []string{}
				for r := range roles {
					v.Accounts[u] = append(v.Accounts[u], r)
				}
				slices.Sort(v.Accounts[u])
			}
			for _, us := range s.wg.Sessions() {
				v.Sessions = append(v.Sessions, us)
			}
		}
		out["bastion"] = v
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Cache-Control", "no-store")
		_ = json.MarshalWrite(rw, out)
	})
	return mux
}

// broker is the stand-in identity broker: it signs a person in without a password and answers with the person id
// and verified address the desk puts in a lease. It is not an OIDC flow; it only gives the story its first step.
func broker() http.Handler {
	people := map[string]string{"ann": "ann@example.test", "bob": "bob@example.test"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sign-in", func(rw http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		email, ok := people[user]
		rw.Header().Set("Content-Type", "application/json")
		if !ok {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.MarshalWrite(rw, map[string]string{"person": "idp:" + user, "email": email})
	})
	return mux
}

type signedIn struct {
	Person string `json:"person"`
	Email  string `json:"email"`
}

func signIn(c *http.Client, base, user string) (signedIn, error) {
	var out signedIn
	resp, err := c.PostForm(base+"/sign-in", url.Values{"user": {user}})
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("the broker refused %s: %s", user, resp.Status)
	}
	return out, json.UnmarshalRead(resp.Body, &out)
}

func newKey() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // the system's random source failed: nothing sensible to do
	}
	return k
}

// Run plays the story: it starts the stand-ins and the agent, records each step in s, and stops everything (and
// removes its temporary directory) before it returns. It returns an error naming the first step that did not happen.
func Run(ctx context.Context, s *Story, o Options) (err error) {
	s.out = o.Out
	defer func() { s.finish(err) }()
	dir, err := os.MkdirTemp("", "relikey-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// Every key is new for this run: the edge's enrolment key, the desk's bundle key and the officer's key.
	enrol := newKey()
	kc := fakes.NewKeyClerk(edge, enrol.Public().(ed25519.PublicKey), []string{"idp:ann", "idp:bob"}, []string{target})
	kc.BundleKey, kc.OfficerKey = newKey(), newKey()
	wg := fakes.NewWarpgate(rand.Text(), map[string][]string{role: {target}})
	wg.IgnoreExpiry = true // as a bastion with its clock set back: every lease end is the agent's own doing
	s.wg = wg
	kcSrv, kcURL, kcPin := kc.Serve()
	defer kcSrv.Close()
	wgSrv, wgURL, wgPin := wg.Serve()
	defer wgSrv.Close()
	brSrv := &http.Server{Handler: broker(), ReadHeaderTimeout: 5 * time.Second}
	brLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go func() { _ = brSrv.Serve(brLn) }()
	defer brSrv.Close()
	pace := func() {
		select {
		case <-time.After(o.Pace):
		case <-ctx.Done():
		}
	}
	s.add("started", "Demo started", "Stand-ins for KeyClerk, Warpgate and the identity broker on loopback; "+
		"keys generated for this run only.")
	pace()

	// The agent, wired as cmd/relikey-agent wires it: pinned TLS with hybrid key exchange to both peers.
	store, err := state.Open(dir, true)
	if err != nil {
		return err
	}
	defer store.Close()
	kcHTTP, err := httpx.New(httpx.Options{Timeout: 5 * time.Second, MinTLS13: true, PinSHA256: kcPin,
		RequireHybrid: true})
	if err != nil {
		return err
	}
	wgHTTP, err := httpx.New(httpx.Options{Timeout: 5 * time.Second, PinSHA256: wgPin, RequireHybrid: true})
	if err != nil {
		return err
	}
	clk := clock.System{}
	a := &agent.Agent{Pins: kc.Pins(), Provider: provider, Mode: agent.Enforce, Version: "relikey-demo", Release: "demo",
		Store: store, Clock: clk, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clerk:   &keyclerk.Client{Base: kcURL, Edge: edge, Key: enrol, HTTP: kcHTTP, Now: clk.Now},
		Bastion: warpgate.Bastion{C: &warpgate.Client{Base: wgURL, Token: wg.Token, HTTP: wgHTTP}},
		Tick:    200 * time.Millisecond, Pull: 300 * time.Millisecond, Grace: time.Second}
	actx, stop := context.WithCancel(ctx)
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = a.Run(actx) }()
	defer func() { stop(); <-stopped }()

	wait := func(what string, f func() bool) error {
		deadline := time.Now().Add(stepWait)
		for !f() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s did not happen within %v", what, stepWait)
			}
			time.Sleep(50 * time.Millisecond)
		}
		return nil
	}
	holds := func(user string) bool {
		v, _ := wg.Snapshot(apply.Marker)
		_, ok := v[user][role]
		return ok
	}

	brClient := &http.Client{Timeout: 5 * time.Second}
	ann, err := signIn(brClient, "http://"+brLn.Addr().String(), "ann")
	if err != nil {
		return err
	}
	s.add("signed-in", "Ann signs in", "The identity broker knows her as "+ann.Person+".")
	pace()

	now := time.Now()
	kc.SetLeases([]fakes.FakeLease{{ID: "L-1", Person: ann.Person, Username: "ann", Email: ann.Email, Target: target,
		Role: role, Class: "low", From: now.Add(-time.Minute), Until: now.Add(time.Hour)}}, nil)
	s.add("lease-granted", "KeyClerk grants a lease", "Lease L-1: ann may use "+role+" on "+target+" for one hour. "+
		"The desk signs it into the edge's next bundle.")
	if err := wait("the lease being applied", func() bool { return holds("ann") }); err != nil {
		return err
	}
	s.add("lease-applied", "The account appears on the bastion", "The agent verified the bundle against its pinned keys "+
		"and created ann on Warpgate with "+role+".")
	pace()

	sid, err := wg.OpenSession("ann", target)
	if err != nil {
		return err
	}
	s.add("session-allowed", "Ann opens a session", "Session "+sid+" to "+target+" runs through the bastion.")
	pace()

	kc.SetLeases(nil, []string{"L-1"})
	s.add("lease-revoked", "The lease is revoked", "KeyClerk lists L-1 as revoked in the next bundle.")
	if err := wait("the revocation removing the access", func() bool {
		return !wg.SessionOpen(sid) && !wg.UserExists("ann", apply.Marker)
	}); err != nil {
		return err
	}
	s.add("access-removed", "The access is gone", "The agent closed session "+sid+" and removed ann from the bastion.")
	pace()

	bob, err := signIn(brClient, "http://"+brLn.Addr().String(), "bob")
	if err != nil {
		return err
	}
	now = time.Now()
	until := now.Add(4 * time.Second).Truncate(time.Second).Add(time.Second)
	kc.SetLeases([]fakes.FakeLease{{ID: "L-2", Person: bob.Person, Username: "bob", Email: bob.Email, Target: target,
		Role: role, Class: "low", From: now.Add(-time.Minute), Until: until}}, []string{"L-1"})
	if err := wait("bob's short lease being applied", func() bool { return holds("bob") }); err != nil {
		return err
	}
	kc.SetFaults(true, false)
	s.add("desk-offline", "The edge loses its network", "Bob holds a short lease (L-2, until "+
		until.UTC().Format(time.TimeOnly)+" UTC); KeyClerk now answers nothing.")
	if err := wait("the offline lease end", func() bool {
		return !holds("bob") && !wg.UserExists("bob", apply.Marker)
	}); err != nil {
		return err
	}
	if _, refused := kc.Counts(); refused > 0 {
		return fmt.Errorf("the desk refused %d of the agent's requests", refused)
	}
	s.add("lease-ended-offline", "The lease still ends on time", "With no desk to ask, the agent ended L-2 from the "+
		"bundle it had verified and removed bob.")
	kc.SetFaults(false, false)
	s.add("done", "End of the demo", "Every key and file of this run is discarded when the demo stops.")
	return nil
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}

func main() {
	headless := flag.Bool("headless", false, "no page: print the steps as JSON lines and exit when the story ends")
	addr := flag.String("addr", "127.0.0.1:0", "the page's loopback address")
	noOpen := flag.Bool("no-open", false, "do not open a browser (print the page's address only)")
	pace := flag.Duration("pace", 2*time.Second, "pause after each step when the page is shown")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	s := &Story{}
	if *headless {
		if err := Run(ctx, s, Options{Out: os.Stdout}); err != nil {
			fmt.Fprintln(os.Stderr, "relikey-demo:", err)
			os.Exit(1)
		}
		return
	}
	host, _, err := net.SplitHostPort(*addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		fmt.Fprintln(os.Stderr, "relikey-demo: -addr must be a loopback address (127.0.0.1:port or [::1]:port)")
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relikey-demo:", err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	u := "http://" + ln.Addr().String() + "/"
	fmt.Println("ReliKey demo (stand-ins only, no real systems): " + u)
	fmt.Println("Press Ctrl-C to stop; nothing is left behind.")
	if !*noOpen {
		openBrowser(u)
	}
	err = Run(ctx, s, Options{Pace: *pace, Out: os.Stdout})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "relikey-demo:", err)
	}
	<-ctx.Done() // keep the page up until Ctrl-C
	_ = srv.Close()
	if err != nil && !errors.Is(err, context.Canceled) {
		os.Exit(1)
	}
}

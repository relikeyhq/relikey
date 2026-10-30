// SPDX-License-Identifier: EUPL-1.2

package fleet

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"relikey/agent/pkg/fleetproto"
	"relikey/fleet/internal/admin"
	"relikey/fleet/internal/enrol"
	"strings"
	"sync"
	"time"

	"relikey/agent/pkg/events"
)

// Server is the fleet service's HTTP side: reports in, the view out.
type Server struct {
	Inv  *Inventory
	Keys map[string]ed25519.PublicKey
	Now  func() time.Time
	Log  *slog.Logger
	Emit func(events.Event) // nil emits nothing
	// Admin, when set, takes edges' presentations for their enrolment slots (decision 0026 point 15).
	Admin *admin.Store

	warned map[string]time.Time // refusal warnings, at most one a minute per peer: no log flood from bad reports
	mu     sync.Mutex
	window time.Time // the enrolment route's current minute, and the presentations taken in it
	tried  int
}

// MaxPresentPerMinute caps presentations on the enrolment route for the whole fleet: a code is single-use and
// enrolment is rare, so beyond it the route answers 429 and the installer retries later.
const MaxPresentPerMinute = 20

func (s *Server) allowPresent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.Now(); now.Sub(s.window) >= time.Minute {
		s.window, s.tried = now, 0
	}
	s.tried++
	return s.tried <= MaxPresentPerMinute
}

// keys are the edges' report keys: the configured ones and those enrolled by code. A name both list with different
// keys is in neither: a second key for an edge is shown and refused, never chosen (0026 point 15).
func (s *Server) keys() map[string]ed25519.PublicKey {
	if s.Admin == nil {
		return s.Keys
	}
	out := maps.Clone(s.Keys)
	for name, h := range s.Admin.Enrolled() {
		k, err := hex.DecodeString(h)
		if err != nil || len(k) != ed25519.PublicKeySize {
			continue
		}
		if have, ok := out[name]; ok && !have.Equal(ed25519.PublicKey(k)) {
			delete(out, name)
			s.Log.Error("an edge enrolled by code carries another key than the configured one: its reports are refused",
				"edge", name, "next", "remove the edge from fleet.json or decommission the slot; keep the one you enrolled")
			continue
		}
		out[name] = ed25519.PublicKey(k)
	}
	return out
}

func (s *Server) warn(peer string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.warned == nil {
		s.warned = map[string]time.Time{}
	}
	if now := s.Now(); now.Sub(s.warned[peer]) >= time.Minute {
		s.warned[peer] = now
		s.Log.Warn("fleet report refused", "peer", peer, "err", err)
	}
}

const maxReport = 64 << 10

// Handler serves POST /fleet/v1/report and GET /fleet/v1/edges.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fleet/v1/report", func(w http.ResponseWriter, r *http.Request) {
		var signed fleetproto.Signed
		if err := json.NewDecoder(io.LimitReader(r.Body, maxReport)).Decode(&signed); err != nil {
			http.Error(w, "a signed report: {report, signature}", http.StatusBadRequest)
			return
		}
		rep, err := fleetproto.Verify(signed, s.keys())
		if err == nil {
			err = s.Inv.Know(rep.Edge) // an edge enrolled by code joins the inventory with its first verified report
		}
		if err == nil {
			err = s.Inv.Accept(rep, s.Now())
		}
		if err != nil {
			s.warn(r.RemoteAddr, err)
			http.Error(w, "refused", http.StatusForbidden) // the reason stays in the service's log
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// An edge presents its key for its slot (point 15): 204 taken in, 409 the slot is already taken (the installer
	// shows it), 403 anything else (the reason is kept on the slot and in the evidence log, never sent back).
	mux.HandleFunc("POST /fleet/v1/enrol", func(w http.ResponseWriter, r *http.Request) {
		if s.Admin == nil {
			http.Error(w, "enrolment is not set up on this fleet", http.StatusNotFound)
			return
		}
		if !s.allowPresent() {
			http.Error(w, "too many presentations: try again in a minute", http.StatusTooManyRequests)
			return
		}
		var p enrol.Presentation
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&p); err != nil {
			http.Error(w, "a presentation: {slot, key, secret, sig}", http.StatusBadRequest)
			return
		}
		switch err := s.Admin.Present(p, r.Header.Get("X-Forwarded-For"), s.Now()); {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, enrol.ErrTaken):
			http.Error(w, "slot already taken", http.StatusConflict)
		default:
			s.warn(r.RemoteAddr, err)
			http.Error(w, "refused", http.StatusForbidden)
		}
	})
	mux.HandleFunc("GET /fleet/v1/edges", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"basis": "self-reported, not attested (no clerk facts yet)",
			"edges": s.Inv.View()})
	})
	return LoopbackOnly(mux)
}

// Watch sweeps for silence every interval until stop, emitting an event per state change.
func (s *Server) Watch(interval time.Duration, stop <-chan struct{}) {
	prev := map[string]string{}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, tr := range s.Inv.Sweep(s.Now(), prev) {
			s.emitTransition(tr)
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

func (s *Server) emitTransition(tr Transition) {
	if s.Emit == nil {
		return
	}
	typ, outcome, severity, activity, status := "relikey.edge.silent.v1", events.Failure, events.Warning, 1, "New"
	if tr.To == "ok" {
		typ, outcome, severity, activity, status = "relikey.edge.back.v1", events.Success, events.Info, 3, "Resolved"
	}
	ev, err := events.NewFor("relikey-fleet", "urn:relikey:fleet", typ, "edge:"+tr.Edge+"/fleet", outcome, severity,
		tr.From+"->"+tr.To, s.Now(), map[string]any{"class_uid": 2004, "category_uid": 2, "class_name": "Detection Finding",
			"activity_id": activity, "status": status, "severity_id": 3,
			"metadata":     map[string]any{"version": "1.6.0", "product": map[string]any{"name": "ReliKey fleet service", "vendor_name": "ReliKey"}},
			"finding_info": map[string]any{"uid": "silent:" + tr.Edge, "title": "an edge stopped reporting to the fleet"}})
	if err != nil {
		s.Log.Error("event not emitted", "err", err)
		return
	}
	s.Emit(ev)
}

// LoopbackOnly answers only requests addressed to a loopback name or address: a page in a browser on the core host,
// whose attacker name was rebound to 127.0.0.1 in DNS, sends its own name as Host and is refused (GUI red team
// 2026-10-25, A2). The front forwards with Host set to the loopback address (Caddyfile).
func LoopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); !(host == "localhost" || (ip != nil && ip.IsLoopback())) {
			http.Error(w, "not this host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

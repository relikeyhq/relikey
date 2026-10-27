// SPDX-License-Identifier: EUPL-1.2

package fleet

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
		rep, err := fleetproto.Verify(signed, s.Keys)
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

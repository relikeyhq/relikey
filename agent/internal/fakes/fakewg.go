// SPDX-License-Identifier: EUPL-1.2

// Package fakes holds in-memory stand-ins for Warpgate's admin API and KeyClerk's edge
// routes, for tests and the soak harness. They follow the real routes and status codes
// the agent uses (Warpgate main a2570d76 admin OpenAPI; KeyClerk v0.19.0 interface),
// and can inject faults. They are never part of the shipped agent.
package fakes

import (
	"encoding/json/v2"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"time"

	"relikey/agent/internal/warpgate"
)

const wgBase = "/@warpgate/admin/api"

// Warpgate is a fake admin API. Zero value is not usable: use NewWarpgate.
type Warpgate struct {
	mu       sync.Mutex
	Token    string
	Now      func() time.Time
	FailRate float64 // share of requests answered 503
	Down     bool    // every request 503
	// IgnoreExpiry keeps expired assignments active, as a Warpgate whose clock was set
	// back would: the agent must then end leases itself.
	IgnoreExpiry bool
	users        map[string]warpgate.User
	roles        map[string]string                // id -> name
	assign       map[string]map[string]*time.Time // user id -> role id -> expires
	revoked      map[string]map[string]bool       // user id -> role id: removed, kept as inactive (Warpgate's soft delete)
	sso          map[string][]warpgate.SSOCredential
	keys         map[string][]warpgate.PublicKeyCredential
	sessions     map[string]*fakeSession
	targetRoles  map[string][]string // target id -> role ids
	seq          int
	defaults     []string            // role ids every new user gets, as Warpgate's is_default roles
	params       warpgate.Parameters // as a stock Warpgate ships: self-service on, password SSH on, no token limit
	Requests     int
	Failed       int
	// Refuse answers 503 to the requests it matches, as an overloaded or broken endpoint would (stack attack tests).
	Refuse func(method, path string) bool
}

type fakeSession struct {
	warpgate.Session
	closed bool
}

// NewWarpgate has the given roles (name -> the target ids it reaches).
func NewWarpgate(token string, roles map[string][]string) *Warpgate {
	w := &Warpgate{Token: token, Now: time.Now, users: map[string]warpgate.User{}, roles: map[string]string{},
		assign: map[string]map[string]*time.Time{}, revoked: map[string]map[string]bool{}, sso: map[string][]warpgate.SSOCredential{},
		keys:     map[string][]warpgate.PublicKeyCredential{},
		sessions: map[string]*fakeSession{}, targetRoles: map[string][]string{},
		params: warpgate.Parameters{AllowOwnCredentialManagement: true, SSHClientAuthPassword: true}}
	for name, targets := range roles {
		id := w.id("role")
		w.roles[id] = name
		for _, t := range targets {
			w.targetRoles[t] = append(w.targetRoles[t], id)
		}
	}
	return w
}

func (w *Warpgate) id(kind string) string { w.seq++; return fmt.Sprintf("%s-%06d", kind, w.seq) }

// AddUser adds a user the way an operator would (for unmanaged-user tests).
func (w *Warpgate) AddUser(username, description string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := w.id("user")
	w.users[id] = warpgate.User{ID: id, Username: username, Description: description}
	return id
}

// OpenSession starts a session for a user on a target, as a sign-in would.
func (w *Warpgate) OpenSession(username, targetID string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, u := range w.users {
		if u.Username == username {
			id := w.id("session")
			w.sessions[id] = &fakeSession{Session: warpgate.Session{ID: id, Username: username, UserID: u.ID,
				TargetSessions: []warpgate.TargetSession{{TargetID: targetID, Started: w.Now()}}}}
			return id, nil
		}
	}
	return "", fmt.Errorf("no user %s", username)
}

// OpenSigningIn opens a session that has not authenticated yet: no user, no target (Warpgate while an SSH
// sign-in waits for its out-of-band approval in the browser).
func (w *Warpgate) OpenSigningIn() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := w.id("session")
	w.sessions[id] = &fakeSession{Session: warpgate.Session{ID: id}}
	return id
}

// SessionOpen reports whether a session is still open.
func (w *Warpgate) SessionOpen(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.sessions[id]
	return s != nil && !s.closed
}

// View is a snapshot of the managed state for assertions: username -> role -> expires.
type View map[string]map[string]time.Time

// Snapshot returns users with the given description and their active roles.
func (w *Warpgate) Snapshot(description string) (View, map[string][]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	v, emails := View{}, map[string][]string{}
	for _, u := range w.users {
		if u.Description != description {
			continue
		}
		roles := map[string]time.Time{}
		for rid, exp := range w.assign[u.ID] {
			if !w.revoked[u.ID][rid] && (w.IgnoreExpiry || exp == nil || exp.After(w.Now())) {
				e := time.Time{}
				if exp != nil {
					e = *exp
				}
				roles[w.roles[rid]] = e
			}
		}
		v[u.Username] = roles
		for _, c := range w.sso[u.ID] {
			emails[u.Username] = append(emails[u.Username], c.Email)
		}
	}
	return v, emails
}

// Keys returns the public keys a user signs in with, by username.
func (w *Warpgate) Keys(username string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, u := range w.users {
		if u.Username == username {
			for _, k := range w.keys[u.ID] {
				out = append(out, k.OpenSSHPublicKey)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Counts returns requests served and failed.
func (w *Warpgate) Counts() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Requests, w.Failed
}

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	if v != nil {
		_ = json.MarshalWrite(rw, v)
	}
}

// Handler serves the admin API.
func (w *Warpgate) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, f func(rw http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(pattern, func(rw http.ResponseWriter, r *http.Request) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.Requests++
			if r.Header.Get("X-Warpgate-Token") != w.Token {
				writeJSON(rw, 401, map[string]string{"error": "unauthorized"})
				return
			}
			if w.Down || (w.FailRate > 0 && rand.Float64() < w.FailRate) || (w.Refuse != nil && w.Refuse(r.Method, r.URL.Path)) {
				w.Failed++
				writeJSON(rw, 503, map[string]string{"error": "injected fault"})
				return
			}
			f(rw, r)
		})
	}
	h("GET "+wgBase+"/parameters", func(rw http.ResponseWriter, r *http.Request) { writeJSON(rw, 200, w.params) })
	h("PUT "+wgBase+"/parameters", func(rw http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if json.UnmarshalRead(r.Body, &in) != nil {
			writeJSON(rw, 400, nil)
			return
		}
		if v, ok := in["allow_own_credential_management"].(bool); ok {
			w.params.AllowOwnCredentialManagement = v
		}
		if v, ok := in["ssh_client_auth_password"].(bool); ok {
			w.params.SSHClientAuthPassword = v
		}
		if v, ok := in["max_api_token_duration_seconds"].(float64); ok {
			n := int64(v)
			w.params.MaxAPITokenDurationSeconds = &n
		}
		writeJSON(rw, 200, w.params)
	})
	h("GET "+wgBase+"/users", func(rw http.ResponseWriter, r *http.Request) {
		out := []warpgate.User{}
		for _, u := range w.users {
			out = append(out, u)
		}
		slices.SortFunc(out, func(a, b warpgate.User) int { return compareStr(a.ID, b.ID) })
		writeJSON(rw, 200, out)
	})
	h("POST "+wgBase+"/users", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Username    string `json:"username"`
			Description string `json:"description"`
		}
		if json.UnmarshalRead(r.Body, &in) != nil || in.Username == "" {
			writeJSON(rw, 400, nil)
			return
		}
		for _, u := range w.users {
			if u.Username == in.Username {
				writeJSON(rw, 400, map[string]string{"error": "username taken"})
				return
			}
		}
		id := w.id("user")
		u := warpgate.User{ID: id, Username: in.Username, Description: in.Description}
		w.users[id] = u
		for _, rid := range w.defaults {
			if w.assign[id] == nil {
				w.assign[id] = map[string]*time.Time{}
			}
			w.assign[id][rid] = nil
		}
		writeJSON(rw, 201, u)
	})
	h("DELETE "+wgBase+"/users/{id}", func(rw http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := w.users[id]; !ok {
			writeJSON(rw, 404, nil)
			return
		}
		delete(w.users, id)
		delete(w.assign, id)
		delete(w.sso, id)
		delete(w.keys, id)
		writeJSON(rw, 204, nil)
	})
	h("GET "+wgBase+"/roles", func(rw http.ResponseWriter, r *http.Request) {
		out := []warpgate.Role{}
		for id, n := range w.roles {
			out = append(out, warpgate.Role{ID: id, Name: n})
		}
		writeJSON(rw, 200, out)
	})
	h("GET "+wgBase+"/users/{id}/roles", func(rw http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := w.users[id]; !ok {
			writeJSON(rw, 404, nil)
			return
		}
		out := []warpgate.RoleAssignment{}
		for rid, exp := range w.assign[id] {
			out = append(out, warpgate.RoleAssignment{ID: rid, Name: w.roles[rid], ExpiresAt: exp,
				IsActive: !w.revoked[id][rid] && (w.IgnoreExpiry || exp == nil || exp.After(w.Now()))})
		}
		writeJSON(rw, 200, out)
	})
	setRole := func(create bool) func(rw http.ResponseWriter, r *http.Request) {
		return func(rw http.ResponseWriter, r *http.Request) {
			id, rid := r.PathValue("id"), r.PathValue("rid")
			if _, ok := w.users[id]; !ok || w.roles[rid] == "" {
				writeJSON(rw, 404, nil)
				return
			}
			var in struct {
				ExpiresAt *time.Time `json:"expires_at"`
			}
			_ = json.UnmarshalRead(r.Body, &in)
			if w.assign[id] == nil {
				w.assign[id] = map[string]*time.Time{}
			}
			_, exists := w.assign[id][rid]
			if create && exists && !w.revoked[id][rid] {
				writeJSON(rw, 409, nil)
				return
			}
			if create && w.revoked[id][rid] {
				delete(w.revoked[id], rid) // a POST reactivates a removed assignment (201)
			}
			if !create && !exists {
				writeJSON(rw, 404, nil)
				return
			}
			w.assign[id][rid] = in.ExpiresAt
			writeJSON(rw, map[bool]int{true: 201, false: 200}[create], nil)
		}
	}
	h("POST "+wgBase+"/users/{id}/roles/{rid}", setRole(true))
	h("PUT "+wgBase+"/users/{id}/roles/{rid}", setRole(false))
	h("DELETE "+wgBase+"/users/{id}/roles/{rid}", func(rw http.ResponseWriter, r *http.Request) {
		id, rid := r.PathValue("id"), r.PathValue("rid")
		if _, ok := w.assign[id][rid]; !ok || w.revoked[id][rid] {
			writeJSON(rw, 404, nil)
			return
		}
		if w.revoked[id] == nil {
			w.revoked[id] = map[string]bool{}
		}
		w.revoked[id][rid] = true // soft delete: still listed, inactive
		writeJSON(rw, 204, nil)
	})
	h("GET "+wgBase+"/users/{id}/credentials/sso", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, 200, append([]warpgate.SSOCredential{}, w.sso[r.PathValue("id")]...))
	})
	h("POST "+wgBase+"/users/{id}/credentials/sso", func(rw http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := w.users[id]; !ok {
			writeJSON(rw, 404, nil)
			return
		}
		var in struct {
			Provider string `json:"provider"`
			Email    string `json:"email"`
		}
		_ = json.UnmarshalRead(r.Body, &in)
		c := warpgate.SSOCredential{ID: w.id("sso"), Provider: in.Provider, Email: in.Email}
		w.sso[id] = append(w.sso[id], c)
		writeJSON(rw, 201, c)
	})
	h("DELETE "+wgBase+"/users/{id}/credentials/sso/{cid}", func(rw http.ResponseWriter, r *http.Request) {
		id, cid := r.PathValue("id"), r.PathValue("cid")
		i := slices.IndexFunc(w.sso[id], func(c warpgate.SSOCredential) bool { return c.ID == cid })
		if i < 0 {
			writeJSON(rw, 404, nil)
			return
		}
		w.sso[id] = slices.Delete(w.sso[id], i, i+1)
		writeJSON(rw, 204, nil)
	})
	h("GET "+wgBase+"/sessions", func(rw http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("username")
		items := []warpgate.Session{}
		for _, s := range w.sessions {
			if !s.closed && (user == "" || s.Username == user) {
				items = append(items, s.Session)
			}
		}
		slices.SortFunc(items, func(a, b warpgate.Session) int { return compareStr(a.ID, b.ID) })
		total := len(items)
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil || limit <= 0 {
			limit = 100
		}
		items = items[min(offset, total):min(offset+limit, total)]
		writeJSON(rw, 200, map[string]any{"items": items, "offset": offset, "total": total})
	})
	h("GET "+wgBase+"/users/{id}/credentials/public-keys", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, 200, append([]warpgate.PublicKeyCredential{}, w.keys[r.PathValue("id")]...))
	})
	h("POST "+wgBase+"/users/{id}/credentials/public-keys", func(rw http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := w.users[id]; !ok {
			writeJSON(rw, 404, nil)
			return
		}
		var in struct {
			Label string `json:"label"`
			Key   string `json:"openssh_public_key"`
		}
		_ = json.UnmarshalRead(r.Body, &in)
		c := warpgate.PublicKeyCredential{ID: w.id("key"), Label: in.Label, OpenSSHPublicKey: in.Key}
		w.keys[id] = append(w.keys[id], c)
		writeJSON(rw, 201, c)
	})
	h("DELETE "+wgBase+"/users/{id}/credentials/public-keys/{cid}", func(rw http.ResponseWriter, r *http.Request) {
		id, cid := r.PathValue("id"), r.PathValue("cid")
		i := slices.IndexFunc(w.keys[id], func(c warpgate.PublicKeyCredential) bool { return c.ID == cid })
		if i < 0 {
			writeJSON(rw, 404, nil)
			return
		}
		w.keys[id] = slices.Delete(w.keys[id], i, i+1)
		writeJSON(rw, 204, nil)
	})
	h("GET "+wgBase+"/role/{id}/targets", func(rw http.ResponseWriter, r *http.Request) {
		rid := r.PathValue("id")
		if _, ok := w.roles[rid]; !ok {
			writeJSON(rw, 404, nil)
			return
		}
		out := []warpgate.Target{}
		for t, rids := range w.targetRoles {
			if slices.Contains(rids, rid) {
				out = append(out, warpgate.Target{ID: t, Name: t}) // the fake's target ids are their names
			}
		}
		slices.SortFunc(out, func(a, b warpgate.Target) int { return compareStr(a.ID, b.ID) })
		writeJSON(rw, 200, out)
	})
	h("GET "+wgBase+"/targets/{id}/roles", func(rw http.ResponseWriter, r *http.Request) {
		out := []warpgate.Role{}
		for _, rid := range w.targetRoles[r.PathValue("id")] {
			out = append(out, warpgate.Role{ID: rid, Name: w.roles[rid]})
		}
		writeJSON(rw, 200, out)
	})
	h("POST "+wgBase+"/sessions/{id}/close", func(rw http.ResponseWriter, r *http.Request) {
		s := w.sessions[r.PathValue("id")]
		if s == nil {
			writeJSON(rw, 404, nil)
			return
		}
		s.closed = true
		writeJSON(rw, 201, nil)
	})
	return mux
}

func compareStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Serve starts the fake on a loopback TLS listener; the URL and the certificate pin
// are what the agent's configuration takes.
func (w *Warpgate) Serve() (srv *httptest.Server, base, pin string) {
	srv = httptest.NewTLSServer(w.Handler())
	return srv, srv.URL + wgBase, certPin(srv)
}

// Sessions returns the open sessions: id -> username and target.
func (w *Warpgate) Sessions() map[string][2]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string][2]string{}
	for id, s := range w.sessions {
		if !s.closed && len(s.TargetSessions) > 0 {
			out[id] = [2]string{s.Username, s.TargetSessions[0].TargetID}
		}
	}
	return out
}

// UserExists reports whether a user with that name and description exists.
func (w *Warpgate) UserExists(username, description string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, u := range w.users {
		if u.Username == username && u.Description == description {
			return true
		}
	}
	return false
}

// AssignRole gives a user a role the way an operator would, behind the agent's back (finding 8 tests).
func (w *Warpgate) AssignRole(userID, role string, expires *time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, n := range w.roles {
		if n == role {
			if w.assign[userID] == nil {
				w.assign[userID] = map[string]*time.Time{}
			}
			w.assign[userID][id] = expires
		}
	}
}

// SetFaults changes the fault injection safely while serving.
func (w *Warpgate) SetFaults(down bool, failRate float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Down, w.FailRate = down, failRate
}

// DefaultRole marks a role as given to every new user (Warpgate's is_default).
func (w *Warpgate) DefaultRole(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, n := range w.roles {
		if n == name {
			w.defaults = append(w.defaults, id)
		}
	}
}

// SetParameters sets the fake's parameters, as an administrator (or a stock install) would.
func (w *Warpgate) SetParameters(p warpgate.Parameters) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.params = p
}

// GetParameters returns the fake's parameters.
func (w *Warpgate) GetParameters() warpgate.Parameters {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.params
}

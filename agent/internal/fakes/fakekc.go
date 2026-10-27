// SPDX-License-Identifier: EUPL-1.2

package fakes

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"relikey/agent/internal/kcedge"
)

// Seal is keyclerk.edge.seal: format and key id added, canonical bytes signed.
func Seal(key ed25519.PrivateKey, obj kcedge.Object, format string) kcedge.Sealed {
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	body := kcedge.Object{}
	for k, v := range obj {
		body[k] = v
	}
	body["format"], body["key_id"] = format, kcedge.KeyID(pub)
	raw := kcedge.Encode(body)
	return kcedge.Sealed{Bytes: base64.StdEncoding.EncodeToString(raw), Signature: hex.EncodeToString(ed25519.Sign(key, raw)),
		Key: pub, KeyID: kcedge.KeyID(pub)}
}

// Key is a fixed test key from a seed byte, as KeyClerk's vectors use.
func Key(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func Hex(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

// FakeLease is a lease the fake desk grants.
type FakeLease struct {
	ID, Person, Username, Email, Target, Role, Class string
	From, Until                                      time.Time
}

// FakeVisit is a visit lease the fake desk grants (KeyClerk 0014 edge_visit_leases).
type FakeVisit struct {
	ID, Person, Username, SSHKey, Role string
	Targets                            []string
	From, Until                        time.Time
}

func strList(xs []string) []kcedge.Value {
	out := []kcedge.Value{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// KeyClerk is a fake desk for one edge.
type KeyClerk struct {
	mu        sync.Mutex
	Edge      string
	Enrolment ed25519.PublicKey
	BundleKey ed25519.PrivateKey
	// Protocol13: leases carry email null and the address is fetched (edge protocol 1.3); EmailFetches counts them.
	Protocol13   bool
	EmailFetches int
	OfficerKey   ed25519.PrivateKey
	Now          func() time.Time
	Ceiling      kcedge.Object
	Horizons     map[string]int64
	// governed, when set, is carried as governed_roles (KeyClerk decision 0025); nil leaves the member out.
	governed *[]string
	Leases   []FakeLease
	Visits   []FakeVisit
	Revoked  []string

	Down bool // 503
	// NoLongPoll answers a long-poll at once, as a desk older than KeyClerk 0026 does.
	NoLongPoll bool
	// Held counts the long-polls the desk held.
	Held      int
	ReplayOld bool // answer with the previous bundle (must be refused by the agent)
	Ended     bool // 410 with a sealed ended notice
	// EndedKeys are the enrolment key ids the ended notice names; nil names the edge's
	// own key (a notice for other keys must be ignored, AG-18).
	EndedKeys []string

	// Module is the policy module the bundle names by hash and the module route serves.
	Module        []byte
	ModuleFetches int

	serial  int64
	last    *kcedge.Sealed
	prev    *kcedge.Sealed
	nonces  map[string]time.Time
	Pulls   int
	Refused int
	Reports []jsontext.Value
}

// NewKeyClerk has an officer-signed ceiling admitting the given persons and targets.
func NewKeyClerk(edge string, enrolment ed25519.PublicKey, persons, targets []string) *KeyClerk {
	k := &KeyClerk{Edge: edge, Enrolment: enrolment, BundleKey: Key(1), OfficerKey: Key(2), Now: time.Now,
		Horizons: map[string]int64{"low": 168, "elevated": 24, "privileged": 1}, nonces: map[string]time.Time{}}
	k.Module = []byte("\x00asm\x01\x00\x00\x00") // the smallest valid WebAssembly module
	k.Ceiling = kcedge.Object{"edge": edge, "serial": kcedge.Number("1"),
		"persons": strList(persons), "roles": []kcedge.Value{}, "targets": strList(targets),
		"classes": strList([]string{"low", "elevated", "privileged"}), "max_lease_hours": kcedge.Number("720"),
		"max_offline_hours": kcedge.Number("12"), "profile": "basic", "remote_reach": "off",
		"ports": []kcedge.Value{kcedge.Number("22")}, "signed_at": iso(time.Now().Add(-time.Hour))}
	return k
}

// Pins are what the edge pins on site for this desk.
func (k *KeyClerk) Pins() kcedge.Pins {
	return kcedge.Pins{Edge: k.Edge, BundleKey: Hex(k.BundleKey), OfficerKey: Hex(k.OfficerKey)}
}

// LongPolls returns the pulls answered and the long-polls held.
func (k *KeyClerk) LongPolls() (pulls, held int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.Pulls, k.Held
}

// Serial is the newest serial issued.
func (k *KeyClerk) Serial() int64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.serial
}

// SetVisits replaces the visit leases the desk grants; the next pull gets a new bundle.
func (k *KeyClerk) SetVisits(vs []FakeVisit) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.last != nil {
		k.prev = k.last
	}
	k.Visits, k.last = vs, nil
}

// SetLeases replaces what the desk grants; the next pull gets a new bundle.
func (k *KeyClerk) SetLeases(ls []FakeLease, revoked []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.last != nil {
		k.prev = k.last
	}
	k.Leases, k.Revoked, k.last = ls, revoked, nil
}

func (k *KeyClerk) bundle() kcedge.Sealed {
	if k.last != nil {
		return *k.last
	}
	k.serial++
	leases := []kcedge.Value{}
	for _, l := range k.Leases {
		var email kcedge.Value = l.Email
		if k.Protocol13 {
			email = nil
		}
		leases = append(leases, kcedge.Object{"lease_id": l.ID, "person": l.Person, "username": l.Username,
			"email": email, "target": l.Target, "role": l.Role, "class": l.Class, "roles": []kcedge.Value{},
			"from": iso(l.From), "until": iso(l.Until)})
	}
	visits := []kcedge.Value{}
	for _, v := range k.Visits {
		visits = append(visits, kcedge.Object{"lease_id": v.ID, "person": v.Person, "username": v.Username,
			"ssh_key": v.SSHKey, "targets": strList(v.Targets), "role": v.Role, "from": iso(v.From), "until": iso(v.Until)})
	}
	hz := kcedge.Object{}
	for c, h := range k.Horizons {
		hz[c] = kcedge.Number(strconv.FormatInt(h, 10))
	}
	c := Seal(k.OfficerKey, k.Ceiling, kcedge.CeilingFormat) // the officer seals; the bundle carries it as sealed
	sum := sha256.Sum256(k.Module)
	s := Seal(k.BundleKey, kcedge.Object{"edge": k.Edge, "serial": kcedge.Number(strconv.FormatInt(k.serial, 10)),
		"issued": iso(k.Now()), "horizons": hz, "leases": leases, "visit_leases": visits,
		"revoked": strList(k.Revoked),
		"ceiling": kcedge.Object{"bytes": c.Bytes, "signature": c.Signature, "key": c.Key, "key_id": c.KeyID},
		"policy": kcedge.Object{"modules": kcedge.Object{"ceiling": kcedge.Object{"sha256": hex.EncodeToString(sum[:])}},
			"release": nil, "entrypoints": []kcedge.Value{}}},
		kcedge.BundleFormat)
	if k.governed != nil {
		gr := []kcedge.Value{}
		for _, r := range *k.governed {
			gr = append(gr, kcedge.Object{"displayName": r})
		}
		obj := kcedge.Object{}
		raw, _ := base64.StdEncoding.DecodeString(s.Bytes)
		v, _ := kcedge.Parse(raw)
		for name, val := range v.(kcedge.Object) {
			if name != "format" && name != "key_id" {
				obj[name] = val
			}
		}
		obj["governed_roles"] = gr
		s = Seal(k.BundleKey, obj, kcedge.BundleFormat)
	}
	k.last = &s
	return s
}

// SetGoverned makes the next bundles carry these governed roles (KeyClerk decision 0025).
func (k *KeyClerk) SetGoverned(roles []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.governed = &roles
	k.last = nil // the next pull gets a new bundle
}

var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// checkRequest is keyclerk.edge.check_request.
func (k *KeyClerk) checkRequest(r *http.Request, body []byte) error {
	parts := strings.Split(r.Header.Get(kcedge.RequestHeader), ";")
	if len(parts) != 4 || parts[0] != k.Edge || !nonceRE.MatchString(parts[2]) {
		return fmt.Errorf("malformed header")
	}
	secs, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || k.Now().Sub(time.Unix(secs, 0)).Abs() > kcedge.Skew {
		return fmt.Errorf("clock skew")
	}
	sig, err := hex.DecodeString(parts[3])
	msg := kcedge.RequestMessage(parts[0], r.Method, r.URL.RequestURI(), secs, parts[2], body)
	if err != nil || !ed25519.Verify(k.Enrolment, msg, sig) {
		return fmt.Errorf("bad signature")
	}
	now := k.Now()
	for n, t := range k.nonces {
		if now.Sub(t) > 2*kcedge.Skew {
			delete(k.nonces, n)
		}
	}
	if _, seen := k.nonces[parts[2]]; seen {
		return fmt.Errorf("replayed nonce")
	}
	k.nonces[parts[2]] = now
	return nil
}

// Handler serves the edge routes the agent calls.
func (k *KeyClerk) Handler() http.Handler {
	mux := http.NewServeMux()
	guard := func(f func(rw http.ResponseWriter, r *http.Request, body []byte)) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			k.mu.Lock()
			defer k.mu.Unlock()
			if k.Down {
				writeJSON(rw, 503, nil)
				return
			}
			if err := k.checkRequest(r, body); err != nil {
				k.Refused++
				writeJSON(rw, 401, map[string]string{"error": err.Error()})
				return
			}
			f(rw, r, body)
		}
	}
	mux.HandleFunc("GET /api/v1/edge/bundle", guard(func(rw http.ResponseWriter, r *http.Request, _ []byte) {
		k.Pulls++
		if k.Ended {
			keys := k.EndedKeys
			if keys == nil {
				keys = []string{kcedge.KeyID(hex.EncodeToString(k.Enrolment))}
			}
			writeJSON(rw, 410, Seal(k.BundleKey, kcedge.Object{"edge": k.Edge, "ended": iso(k.Now()), "reason": "decommissioned",
				"enrolment_keys": strList(keys)}, kcedge.EndedFormat))
			return
		}
		q := r.URL.Query()
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		wait, _ := strconv.Atoi(q.Get("wait"))
		if !k.NoLongPoll && wait > 0 && after > 0 && k.last != nil && k.serial == after {
			// Held until the content changes (a setter clears last) or the wait ends; the lock is released meanwhile.
			k.Held++
			deadline := time.Now().Add(time.Duration(min(wait, 55)) * time.Second)
			for k.last != nil && time.Now().Before(deadline) && r.Context().Err() == nil {
				k.mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				k.mu.Lock()
			}
			k.last = nil // always a fresh bundle with a new serial, as the desk answers
		}
		s := k.bundle()
		if k.ReplayOld && k.prev != nil {
			s = *k.prev
		}
		writeJSON(rw, 200, s)
	}))
	mux.HandleFunc("GET /api/v1/edge/module/{sha}", guard(func(rw http.ResponseWriter, r *http.Request, _ []byte) {
		sum := sha256.Sum256(k.Module)
		if r.PathValue("sha") != hex.EncodeToString(sum[:]) {
			writeJSON(rw, 404, map[string]string{"error": "no such module"})
			return
		}
		k.ModuleFetches++
		writeJSON(rw, 200, map[string]string{"name": "ceiling", "sha256": hex.EncodeToString(sum[:]),
			"wasm": base64.StdEncoding.EncodeToString(k.Module)})
	}))
	mux.HandleFunc("GET /api/v1/edge/lease/{id}/email", guard(func(rw http.ResponseWriter, r *http.Request, _ []byte) {
		k.EmailFetches++
		nonce := strings.Split(r.Header.Get(kcedge.RequestHeader), ";")[2]
		for _, l := range k.Leases {
			if l.ID == r.PathValue("id") && !slices.Contains(k.Revoked, l.ID) {
				var email kcedge.Value
				if l.Email != "" {
					email = l.Email
				}
				writeJSON(rw, 200, Seal(k.BundleKey, kcedge.Object{"edge": k.Edge, "lease_id": l.ID, "person": l.Person,
					"email": email, "nonce": nonce, "issued": iso(k.Now())}, kcedge.EmailFormat))
				return
			}
		}
		writeJSON(rw, 404, map[string]string{"error": "no live lease"})
	}))
	mux.HandleFunc("POST /api/v1/edge/report", guard(func(rw http.ResponseWriter, r *http.Request, body []byte) {
		if len(k.Reports) >= 100 {
			k.Reports = k.Reports[1:]
		}
		k.Reports = append(k.Reports, jsontext.Value(body))
		writeJSON(rw, 200, map[string]bool{"ok": true})
	}))
	return mux
}

// LastReport returns the newest report the edge sent.
func (k *KeyClerk) LastReport() jsontext.Value {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.Reports) == 0 {
		return nil
	}
	return k.Reports[len(k.Reports)-1]
}

// Counts returns pulls and refused requests.
func (k *KeyClerk) Counts() (int, int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.Pulls, k.Refused
}

// Serve starts the fake on a loopback TLS listener.
func (k *KeyClerk) Serve() (srv *httptest.Server, base, pin string) {
	srv = httptest.NewTLSServer(k.Handler())
	return srv, srv.URL, certPin(srv)
}

func certPin(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

// SetFaults changes the desk's behaviour safely while serving.
func (k *KeyClerk) SetFaults(down, replayOld bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.Down, k.ReplayOld = down, replayOld
}

// SetNoLongPoll makes the desk answer a long-poll at once (a desk older than KeyClerk 0026), under the lock the
// handler reads it with.
func (k *KeyClerk) SetNoLongPoll(on bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.NoLongPoll = on
}

// RefusedCount is the number of requests refused (bad signature, replayed nonce, skew).
func (k *KeyClerk) RefusedCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.Refused
}

// SetEnded makes the desk answer 410 with a sealed ended notice (or stop doing so).
func (k *KeyClerk) SetEnded(ended bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.Ended = ended
}

// SetEndedFor answers 410 with a notice naming these enrolment key ids instead of the
// edge's own (a captured notice of another enrolment, AG-18).
func (k *KeyClerk) SetEndedFor(keyIDs []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.Ended, k.EndedKeys = true, keyIDs
}

// ModuleFetchCount is how often the module route served the module.
func (k *KeyClerk) ModuleFetchCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ModuleFetches
}

// SetProtocol13 switches the desk to edge protocol 1.3: leases carry email null, the address is fetched.
func (k *KeyClerk) SetProtocol13(on bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.Protocol13, k.last = on, nil
}

// Fetches is how many e-mail requests the desk answered.
func (k *KeyClerk) Fetches() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.EmailFetches
}

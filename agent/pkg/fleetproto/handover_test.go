// SPDX-License-Identifier: EUPL-1.2

package fleetproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/kcedge"
)

func statement(t *testing.T, next ed25519.PrivateKey, change func(kcedge.Object)) Statement {
	t.Helper()
	var st Statement
	if err := json.Unmarshal(fakes.RotationStatement("plant-a", fakes.Key(2), next, change), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func handover(t *testing.T, old, next ed25519.PrivateKey, at time.Time, st Statement) SignedHandover {
	t.Helper()
	s, err := SignHandover(old, next, Handover{Edge: "plant-a", At: at, Statement: st})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A handover signed by the key the fleet holds and the new one, carrying the desk's statement for the new key,
// verifies and says what the statement says; every other shape is refused with its reason.
func TestAHandoverNeedsBothKeysAndTheStatement(t *testing.T) {
	old, next, now := key("plant-a"), key("plant-a next"), time.Now()
	held := keys()
	good := handover(t, old, next, now, statement(t, next, nil))
	h, f, err := VerifyHandover(good, held, now)
	if err != nil || h.NewKey != fakes.Hex(next) || f.OfficerKey != fakes.Hex(fakes.Key(2)) || f.Officer != "idp:officer" {
		t.Fatalf("a good handover: %v, %+v", err, f)
	}
	thief := key("a thief's key") // signs as the old key without holding it
	notOld := handover(t, thief, next, now, statement(t, next, nil))
	badNew := good
	badNew.NewSignature = handover(t, old, thief, now, statement(t, next, nil)).NewSignature
	raw, _ := base64.StdEncoding.DecodeString(good.Handover)
	tampered := good
	tampered.Handover = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"plant-a"`, `"plant-b"`, 1)))
	for name, tc := range map[string]struct {
		s    SignedHandover
		want string
	}{
		"without the old key's signature":      {notOld, "is not the key the fleet holds"},
		"with the old key's signature forged":  {func() SignedHandover { s := good; s.OldSignature = notOld.OldSignature; return s }(), "old key's signature"},
		"without the new key's signature":      {badNew, "new key's signature"},
		"tampered after signing":               {tampered, "not a known edge"},
		"a stale handover":                     {handover(t, old, next, now.Add(-time.Hour), statement(t, next, nil)), "from ours"},
		"a statement for another key":          {handover(t, old, next, now, statement(t, thief, nil)), "does not name the new key"},
		"a statement for another edge":         {handover(t, old, next, now, statement(t, next, func(o kcedge.Object) { o["edge"] = "plant-b" })), "for edge"},
		"the enrolment statement":              {handover(t, old, next, now, statement(t, next, func(o kcedge.Object) { o["purpose"] = "enrolment" })), "not rotation"},
		"the new key handed over as the old":   {handover(t, old, old, now, statement(t, old, nil)), "the new key is the old one"},
		"a statement the new key did not sign": {handover(t, old, next, now, func() Statement { st := statement(t, next, nil); st.Signatures = st.Signatures[:1]; return st }()), "not signed by exactly its officer and the new key"},
		"a statement with a forged signature": {handover(t, old, next, now, func() Statement {
			st := statement(t, next, nil)
			st.Signatures[0].Signature = strings.Repeat("0", 128)
			return st
		}()), "does not verify"},
	} {
		if _, _, err := VerifyHandover(tc.s, held, now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want a refusal saying %q", name, err, tc.want)
		}
	}
}

// fresh is a report made now: the handover carries its time, which the fleet holds to Skew.
func fresh(seq int64) Report {
	r := report(seq)
	r.At = time.Now()
	return r
}

// fleet is a fleet stand-in: it holds one key per edge, takes reports signed with it and handovers verified against it.
type fleet struct {
	mu        sync.Mutex
	held      map[string]ed25519.PublicKey
	handovers int
	reports   []ed25519.PublicKey // the key each accepted report was signed with
}

func (f *fleet) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/fleet/v1/rotation" {
			var s SignedHandover
			_ = json.NewDecoder(r.Body).Decode(&s)
			if _, _, err := VerifyHandover(s, f.held, time.Now()); err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			f.handovers++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var s Signed
		_ = json.NewDecoder(r.Body).Decode(&s)
		if _, err := Verify(s, f.held); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.reports = append(f.reports, f.held["plant-a"])
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// rotation is the edge's side: the fleet's key, the new one while it waits, and whether the old key was retired.
type rotation struct {
	mu       sync.Mutex
	old, cur ed25519.PrivateKey
	st       Statement
	retired  int
}

func (r *rotation) FleetKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.old != nil {
		return r.old, r.cur
	}
	return r.cur, nil
}
func (r *rotation) Statement() Statement { return r.st }
func (r *rotation) Retire() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.old = nil
	r.retired++
}

// During a rotation the reports go on with the key the fleet holds and the handover follows once; when the fleet
// refuses the old key after an officer's approval, the report goes again with the new key and the old key retires.
func TestTheClientHandsTheKeyOverAndSwitchesOnTheFleetsRefusal(t *testing.T) {
	old, next := key("plant-a"), key("plant-a next")
	f := &fleet{held: keys()}
	srv := f.serve(t)
	rot := &rotation{old: old, cur: next, st: statement(t, next, nil)}
	c := &Client{URL: srv.URL, HTTP: srv.Client(), Rotation: rot}
	for seq := int64(1); seq <= 2; seq++ {
		if err := c.Send(t.Context(), fresh(seq)); err != nil {
			t.Fatalf("report %d while the rotation waits: %v", seq, err)
		}
	}
	if f.handovers != 1 || len(f.reports) != 2 || rot.retired != 0 {
		t.Fatalf("%d handovers, %d reports, %d retired; want the handover once and the reports with the old key",
			f.handovers, len(f.reports), rot.retired)
	}
	f.mu.Lock()
	f.held = map[string]ed25519.PublicKey{"plant-a": next.Public().(ed25519.PublicKey)} // an officer approved
	f.mu.Unlock()
	if err := c.Send(t.Context(), fresh(3)); err != nil || rot.retired != 1 {
		t.Fatalf("the report after the approval: %v, %d retired; want it delivered with the new key, the old retired", err, rot.retired)
	}
	if err := c.Send(t.Context(), fresh(4)); err != nil || f.handovers != 1 {
		t.Fatalf("after the rotation: %v, %d handovers", err, f.handovers)
	}
}

// A handover the fleet does not take is sent again and said apart from the report, which was delivered.
func TestAHandoverTheFleetRefusesIsSentAgain(t *testing.T) {
	old, next := key("plant-a"), key("plant-a next")
	f := &fleet{held: keys()}
	srv := f.serve(t)
	rot := &rotation{old: old, cur: next, st: statement(t, key("not the new key"), nil)}
	c := &Client{URL: srv.URL, HTTP: srv.Client(), Rotation: rot}
	err := c.Send(t.Context(), fresh(1))
	var herr *HandoverError
	if !errors.As(err, &herr) || len(f.reports) != 1 {
		t.Fatalf("got %v with %d reports; want the report delivered and a handover error", err, len(f.reports))
	}
	rot.st = statement(t, next, nil)
	if err := c.Send(t.Context(), fresh(2)); err != nil || f.handovers != 1 {
		t.Fatalf("the handover sent again: %v, %d taken", err, f.handovers)
	}
}

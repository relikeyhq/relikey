// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"relikey/agent/internal/enrolkey"
	"relikey/agent/internal/fakes"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/pkg/fleetproto"
)

// rotationFleet is a fleet stand-in that holds one key for edge-a: reports signed with it are taken, handovers verified
// against it are kept as pending, and approve moves it to the pending new key, as an officer's passkey does.
type rotationFleet struct {
	mu      sync.Mutex
	held    ed25519.PublicKey
	pending string         // the new key handed over (hex)
	byKey   map[string]int // reports taken, by the key (hex) they were signed with
	refused map[string]int // reports refused, by the key the fleet held then
	seqs    []int64        // the accepted reports' sequences, in order
}

func (f *rotationFleet) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		keys := map[string]ed25519.PublicKey{"edge-a": f.held}
		if r.URL.Path == "/fleet/v1/rotation" {
			var s fleetproto.SignedHandover
			if json.UnmarshalRead(r.Body, &s) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			h, _, err := fleetproto.VerifyHandover(s, keys, time.Now())
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			f.pending = h.NewKey
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var s fleetproto.Signed
		if json.UnmarshalRead(r.Body, &s) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rep, err := fleetproto.Verify(s, keys)
		if err == nil && len(f.seqs) > 0 && rep.Seq <= f.seqs[len(f.seqs)-1] {
			err = io.EOF // a replay: the sequence carries across the key change
		}
		if err != nil {
			f.refused[hex.EncodeToString(f.held)]++
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.byKey[hex.EncodeToString(f.held)]++
		f.seqs = append(f.seqs, rep.Seq)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *rotationFleet) count(k ed25519.PrivateKey) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byKey[fakes.Hex(k)]
}

func (f *rotationFleet) approve(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	k, err := hex.DecodeString(f.pending)
	if err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatal("nothing is pending to approve")
	}
	f.held = ed25519.PublicKey(k)
}

// The whole rotation (#26): the desk rotates the edge's key; the agent's next pull is refused, retried with the staged
// key and promoted, and pulls go on; the old key stays refused at the desk. The fleet keeps the old key until an
// officer approves the handover, and the reports go on with it; after the approval the fleet refuses the old key, the
// agent reports with the new one and deletes the old key file. Reports never stop, and their sequence keeps rising.
func TestAnEnrolmentKeyRotationKeepsPullingAndReporting(t *testing.T) {
	old, next := fakes.Key(9), fakes.Key(10)
	dir := t.TempDir()
	cur, nextF, stmt := filepath.Join(dir, "enrolment.key"), filepath.Join(dir, "enrolment.next.key"), filepath.Join(dir, "rotation.json")
	for path, k := range map[string]ed25519.PrivateKey{cur: old, nextF: next} {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(k.Seed())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(stmt, fakes.RotationStatement("edge-a", fakes.Key(2), next, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := enrolkey.Load(enrolkey.Options{Current: cur, Next: nextF, Statement: stmt, Edge: "edge-a",
		OfficerKey: fakes.Hex(fakes.Key(2)), HoldOld: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	fl := &rotationFleet{held: old.Public().(ed25519.PublicKey), byKey: map[string]int{}, refused: map[string]int{}}
	srv := fl.serve(t)
	r := newRigTuned(t, func(a *Agent) {
		a.Clerk.(*keyclerk.Client).Rotation = keys
		a.Fleet = &fleetproto.Client{URL: srv.URL, HTTP: srv.Client(), Rotation: keys}
	})
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role with the old key", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.eventually("reports with the old key", func() bool { return fl.count(old) >= 1 })

	r.kc.SetEnrolment(next.Public().(ed25519.PublicKey)) // the desk's security officer completed the rotation
	r.eventually("the staged key is promoted", func() bool { return keys.Current().Equal(next) })
	if b, _ := os.ReadFile(cur); strings.TrimSpace(string(b)) != hex.EncodeToString(next.Seed()) {
		t.Fatal("the enrolment key's file does not hold the new key")
	}
	if _, err := os.Stat(cur + enrolkey.OldSuffix); err != nil {
		t.Fatal("the old key is not kept for the fleet")
	}
	refused := r.kc.RefusedCount()
	if refused < 1 {
		t.Fatal("the desk never refused the old key")
	}
	pulls, _ := r.kc.Counts()
	r.eventually("pulls go on with the new key", func() bool { p, _ := r.kc.Counts(); return p >= pulls+3 })
	if got := r.kc.RefusedCount(); got != refused {
		t.Fatalf("%d refusals after the promotion, want %d: every request is signed with the new key", got, refused)
	}
	kcHTTP, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, PinSHA256: r.kcPin})
	oldClient := &keyclerk.Client{Base: r.kcURL, Edge: "edge-a", Key: old, HTTP: kcHTTP, Now: time.Now}
	if _, err := oldClient.Pull(t.Context(), 0, 0); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("the old key at the desk after the rotation: %v, want 401", err)
	}

	before := fl.count(old)
	r.eventually("the handover is pending at the fleet", func() bool { fl.mu.Lock(); defer fl.mu.Unlock(); return fl.pending != "" })
	r.eventually("reports go on with the old key while the fleet waits", func() bool { return fl.count(old) >= before+2 })
	if fl.count(next) != 0 {
		t.Fatal("a report was signed with the new key before the fleet took it")
	}

	fl.approve(t) // an officer approved the rotation with their passkey
	r.eventually("reports with the new key", func() bool { return fl.count(next) >= 2 })
	r.eventually("the old key file is deleted", func() bool { _, err := os.Stat(cur + enrolkey.OldSuffix); return os.IsNotExist(err) })
	if _, ok := r.roles("ann")["plc-operator"]; !ok {
		t.Fatal("the lease was lost during the rotation")
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	for i := 1; i < len(fl.seqs); i++ {
		if fl.seqs[i] <= fl.seqs[i-1] {
			t.Fatalf("the report sequence went back across the rotation: %v", fl.seqs)
		}
	}
}

// SPDX-License-Identifier: EUPL-1.2

package keyclerk

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"relikey/agent/internal/fakes"
)

// keys is a rotation holder: the current key, a staged next key, and how often a promotion was asked for.
type keys struct {
	mu            sync.Mutex
	current, next ed25519.PrivateKey
	promoted      int
}

func (k *keys) Current() ed25519.PrivateKey { k.mu.Lock(); defer k.mu.Unlock(); return k.current }
func (k *keys) Next() ed25519.PrivateKey    { k.mu.Lock(); defer k.mu.Unlock(); return k.next }
func (k *keys) Promote(next ed25519.PrivateKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.promoted++
	if k.next != nil && k.next.Equal(next) {
		k.current, k.next = next, nil
	}
}

func desk(t *testing.T, rot Rotation) (*fakes.KeyClerk, *Client) {
	t.Helper()
	kc := fakes.NewKeyClerk("edge-a", fakes.Key(9).Public().(ed25519.PublicKey), []string{"idp:ann"}, []string{"plc"})
	srv, base, _ := kc.Serve()
	t.Cleanup(srv.Close)
	return kc, &Client{Base: base, Edge: "edge-a", Rotation: rot, HTTP: srv.Client(), Now: time.Now}
}

// After the desk's security officer completes a rotation, the desk refuses the old key with 401: the same request
// signed with the staged key is taken, the staged key is promoted, and the next request is signed with it at once.
func TestARefusedKeyIsRetriedWithTheStagedKeyAndPromoted(t *testing.T) {
	rot := &keys{current: fakes.Key(9), next: fakes.Key(10)}
	kc, c := desk(t, rot)
	if _, err := c.Pull(t.Context(), 0, 0); err != nil || rot.promoted != 0 {
		t.Fatalf("before the rotation: %v, %d promotions; want the old key taken and nothing promoted", err, rot.promoted)
	}
	kc.SetEnrolment(fakes.Key(10).Public().(ed25519.PublicKey))
	if got, err := c.Pull(t.Context(), 0, 0); err != nil || got.Bundle == nil {
		t.Fatalf("the pull after the rotation: %v; want the bundle, fetched with the staged key", err)
	}
	if rot.promoted != 1 || !rot.Current().Equal(fakes.Key(10)) {
		t.Fatal("the staged key the desk took was not promoted")
	}
	if !c.EnrolmentKey().Equal(fakes.Key(10).Public()) {
		t.Fatal("the enrolment key an ended notice must name is still the old one")
	}
	if _, err := c.Pull(t.Context(), 0, 0); err != nil || kc.RefusedCount() != 1 {
		t.Fatalf("the next pull: %v, %d refused; want it signed with the new key, the old key's 401 the only refusal",
			err, kc.RefusedCount())
	}
}

// A 401 the staged key does not cure changes nothing: the desk's refusal comes back as it was, and the old key stays.
func TestA401TheStagedKeyDoesNotCureChangesNothing(t *testing.T) {
	rot := &keys{current: fakes.Key(9), next: fakes.Key(10)}
	kc, c := desk(t, rot)
	kc.SetEnrolment(fakes.Key(11).Public().(ed25519.PublicKey)) // the desk holds a key this edge never had
	_, err := c.Pull(t.Context(), 0, 0)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		t.Fatalf("got %v, want the desk's 401", err)
	}
	if rot.promoted != 0 || !rot.Current().Equal(fakes.Key(9)) || !rot.Next().Equal(fakes.Key(10)) {
		t.Fatal("a 401 the staged key did not cure changed the keys")
	}
	if kc.RefusedCount() != 2 {
		t.Fatalf("%d refused, want 2: the old key and the staged one", kc.RefusedCount())
	}
	none := &keys{current: fakes.Key(9)} // nothing staged: the 401 is returned without a second request
	kc, c = desk(t, none)
	kc.SetEnrolment(fakes.Key(10).Public().(ed25519.PublicKey))
	if _, err := c.Pull(t.Context(), 0, 0); !errors.As(err, &se) || se.Status != http.StatusUnauthorized || kc.RefusedCount() != 1 {
		t.Fatalf("with nothing staged: %v, %d refused; want one 401", err, kc.RefusedCount())
	}
}

// An outage on the retry promotes nothing: only the desk's acceptance does.
func TestAnOutageOnTheRetryPromotesNothing(t *testing.T) {
	rot := &keys{current: fakes.Key(9), next: fakes.Key(10)}
	kc, c := desk(t, rot)
	kc.SetEnrolment(fakes.Key(10).Public().(ed25519.PublicKey))
	kc.SetFaults(true, false)
	if _, err := c.Pull(t.Context(), 0, 0); err == nil || rot.promoted != 0 {
		t.Fatalf("a desk that is down: %v, %d promotions; want an error and nothing promoted", err, rot.promoted)
	}
}

// The ended notice is an answer only an identified edge gets: it counts as the desk taking the staged key.
func TestTheEndedNoticeCountsAsAcceptance(t *testing.T) {
	for status, want := range map[int]bool{200: true, 204: true, 410: true, 401: false, 403: false, 404: false, 503: false} {
		if accepted(status) != want {
			t.Errorf("accepted(%d) = %v, want %v", status, !want, want)
		}
	}
}

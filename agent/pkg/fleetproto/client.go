// SPDX-License-Identifier: EUPL-1.2

package fleetproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Client is the edge's side: it signs and sends the report. Send returns only an error, never anything the service
// said: the fleet service is read-only towards edges (decision 0026 point 9), so there is nothing an edge could take
// from it. Every change reaches an edge only as a signed bundle or a signed release.
type Client struct {
	URL  string // the edge-facing name, e.g. https://edge.example:8443 (the routes add /fleet/v1/report)
	HTTP *http.Client
	Key  ed25519.PrivateKey // the edge's enrolment key
	// Rotation, when set, is the edge's enrolment-key rotation (#26), and its keys replace Key: reports are signed with
	// the key the fleet holds, and while the fleet has not taken the new key, the handover goes until it does.
	Rotation Rotation

	mu     sync.Mutex
	handed string // the new key (hex) whose handover the fleet took: not sent again
}

// Rotation is the edge's enrolment-key rotation as the fleet client sees it (agent/internal/enrolkey).
type Rotation interface {
	// FleetKeys returns the key the fleet holds for this edge and, while the fleet has not taken the edge's new key,
	// that key (nil otherwise).
	FleetKeys() (held, next ed25519.PrivateKey)
	// Statement is the desk's rotation statement for the new key, which the handover carries.
	Statement() Statement
	// Retire deletes the old key: the fleet took the new one.
	Retire()
}

// ErrRefused is the fleet's 403: a signature by a key it does not hold, a replay, or a report it will not take.
var ErrRefused = errors.New("refused by the fleet")

// AnswerError is any answer but 204.
type AnswerError struct{ Status int }

func (e *AnswerError) Error() string { return fmt.Sprintf("fleet answered %d", e.Status) }

// Is makes a 403 match ErrRefused.
func (e *AnswerError) Is(target error) bool {
	return target == ErrRefused && e.Status == http.StatusForbidden
}

// HandoverError is a rotation handover the fleet did not take, while the report itself was delivered.
type HandoverError struct{ Err error }

func (e *HandoverError) Error() string {
	return "rotation handover not taken by the fleet: " + e.Err.Error()
}
func (e *HandoverError) Unwrap() error { return e.Err }

// Send signs r and posts it; anything but 204 is an error, and the body is discarded unread beyond a small limit.
// During a rotation it signs with the key the fleet holds. A refusal of that key while the new key waits means an
// officer approved the rotation, so the report goes again with the new key, and once that is taken the old key goes.
// While the new key waits, the handover follows the report until the fleet takes it.
func (c *Client) Send(ctx context.Context, r Report) error {
	if err := r.Check(); err != nil {
		return fmt.Errorf("fleet report not sent: %w", err)
	}
	held, next := c.Key, ed25519.PrivateKey(nil)
	if c.Rotation != nil {
		held, next = c.Rotation.FleetKeys()
	}
	err := c.report(ctx, held, r)
	if next != nil && errors.Is(err, ErrRefused) {
		if err = c.report(ctx, next, r); err == nil {
			c.Rotation.Retire()
			return nil
		}
	}
	if next != nil {
		if herr := c.handover(ctx, held, next, r); herr != nil {
			if err != nil {
				return fmt.Errorf("%w; and the %v", err, herr)
			}
			return herr
		}
	}
	return err
}

func (c *Client) report(ctx context.Context, key ed25519.PrivateKey, r Report) error {
	s, err := Sign(key, r)
	if err != nil {
		return err
	}
	return c.post(ctx, "/fleet/v1/report", s)
}

// handover sends the rotation handover, signed by the key the fleet holds and the new one, until the fleet takes it
// (204); then not again for that key.
func (c *Client) handover(ctx context.Context, held, next ed25519.PrivateKey, r Report) error {
	pub := hex.EncodeToString(next.Public().(ed25519.PublicKey))
	c.mu.Lock()
	done := c.handed == pub
	c.mu.Unlock()
	if done {
		return nil
	}
	s, err := SignHandover(held, next, Handover{Edge: r.Edge, At: r.At, Statement: c.Rotation.Statement()})
	if err == nil {
		err = c.post(ctx, "/fleet/v1/rotation", s)
	}
	if err != nil {
		return &HandoverError{err}
	}
	c.mu.Lock()
	c.handed = pub
	c.mu.Unlock()
	return nil
}

func (c *Client) post(ctx context.Context, path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return &AnswerError{resp.StatusCode}
	}
	return nil
}

// DriftCodes turns the agent's drift lines into codes: the text stays on the edge (decision 0025 point 7).
func DriftCodes(drift []string) []string {
	codes := []string{}
	for _, d := range drift {
		code := "other"
		for _, c := range []struct{ code, needle string }{
			{"rogue_account", "not managed by ReliKey but holds"}, {"unmanaged_conflict", "not managed by ReliKey"},
			{"ceiling", "outside the edge's ceiling"}, {"clock", "clock"}, {"bundle_unverified", "no longer verifies"},
			{"no_bundle", "no verified bundle"}, {"ended", "ended this edge"}, {"unreadable", "could not be read"},
			{"no_email", "carries no e-mail"},
		} {
			if strings.Contains(d, c.needle) {
				code = c.code
				break
			}
		}
		codes = append(codes, code)
	}
	return codes
}

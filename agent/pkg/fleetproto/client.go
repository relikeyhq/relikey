// SPDX-License-Identifier: EUPL-1.2

package fleetproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client is the edge's side: it signs and sends the report. Send returns only an error, never anything the service
// said: the fleet service is read-only towards edges (decision 0026 point 9), so there is nothing an edge could take
// from it. Every change reaches an edge only as a signed bundle or a signed release.
type Client struct {
	URL  string // the edge-facing name, e.g. https://edge.example:8443 (the routes add /fleet/v1/report)
	HTTP *http.Client
	Key  ed25519.PrivateKey // the edge's enrolment key
}

// Send signs r and posts it; anything but 204 is an error, and the body is discarded unread beyond a small limit.
func (c *Client) Send(ctx context.Context, r Report) error {
	if err := r.Check(); err != nil {
		return fmt.Errorf("fleet report not sent: %w", err)
	}
	s, err := Sign(c.Key, r)
	if err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/fleet/v1/report", bytes.NewReader(b))
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
		return fmt.Errorf("fleet answered %d", resp.StatusCode)
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

// SPDX-License-Identifier: EUPL-1.2

// Package keyclerk is the agent's client for KeyClerk's edge routes (interface v0.23.0,
// sections 3, 5 and 7): every request signed with the enrolment key, the bundle pulled,
// policy modules fetched by hash, reports sent. The edge only ever connects out.
package keyclerk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"relikey/agent/internal/httpx"
	"relikey/agent/internal/kcedge"
)

const (
	maxBundle = 4 << 20  // a bundle names its modules by hash: a few KB, leases dominate
	maxModule = 16 << 20 // one policy module, base64 in JSON
)

// Client signs and sends the edge's calls.
type Client struct {
	Base string // e.g. https://keyclerk.example (the routes add /api/v1/edge/...)
	Edge string
	Key  ed25519.PrivateKey
	HTTP *http.Client
	// PollHTTP carries long-polls: the same pin and TLS as HTTP, with timeouts above the desk's hold (55 s). Nil: HTTP.
	PollHTTP *http.Client
	Now      func() time.Time
}

// MaxWait is the longest hold the desk grants a long-poll (KeyClerk decision 0026); a longer wait is clamped.
const MaxWait = 55 * time.Second

// Pulled is the desk's answer to a pull: a bundle, or the sealed notice that the edge
// was ended (410).
type Pulled struct {
	Bundle *kcedge.Sealed
	Ended  *kcedge.Sealed
}

// StatusError is an answer the agent does not act on (an outage, a refusal).
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("keyclerk answered %d: %s", e.Status, e.Body)
}

func (c *Client) call(ctx context.Context, method, path string, body []byte, limit int64) (int, []byte, error) {
	return c.callWith(ctx, c.HTTP, method, path, body, limit)
}

func (c *Client) callWith(ctx context.Context, hc *http.Client, method, path string, body []byte, limit int64) (int, []byte, error) {
	return c.callNonce(ctx, hc, method, path, body, limit, kcedge.NewNonce())
}

func (c *Client) callNonce(ctx context.Context, hc *http.Client, method, path string, body []byte, limit int64, nonce string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	// Sign exactly what is sent: the request URI as built and the body bytes (GE-12).
	req.Header.Set(kcedge.RequestHeader, kcedge.SignRequest(c.Key, c.Edge, method, req.URL.RequestURI(), body,
		c.Now().Unix(), nonce))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	b, err := httpx.ReadAll(resp.Body, limit)
	return resp.StatusCode, b, err
}

// Pull fetches the newest bundle. With after (the serial of the newest bundle the edge accepted) and a wait, it is a
// long-poll: the desk answers when this edge's bundle content differs from that bundle's, or when the wait ends, in
// both cases with a fresh bundle (KeyClerk decision 0026). The parameters are signed exactly as sent, always in the
// order after, wait. A desk that does not know them answers at once, as a plain pull.
func (c *Client) Pull(ctx context.Context, after int64, wait time.Duration) (Pulled, error) {
	path, hc := "/api/v1/edge/bundle", c.HTTP
	if after > 0 && wait >= time.Second {
		path = fmt.Sprintf("%s?after=%d&wait=%d", path, after, int64(min(wait, MaxWait)/time.Second))
		if c.PollHTTP != nil {
			hc = c.PollHTTP
		}
	}
	status, b, err := c.callWith(ctx, hc, http.MethodGet, path, nil, maxBundle)
	if err != nil {
		return Pulled{}, err
	}
	var s kcedge.Sealed
	// A sealed object is exactly {bytes, signature, key, key_id} (0.23.0): an extra
	// member is refused here, never dropped.
	exact := json.RejectUnknownMembers(true)
	switch status {
	case http.StatusOK:
		if err := json.Unmarshal(b, &s, exact); err != nil {
			return Pulled{}, fmt.Errorf("the bundle is not a sealed object: %w", err)
		}
		return Pulled{Bundle: &s}, nil
	case http.StatusGone:
		if err := json.Unmarshal(b, &s, exact); err != nil {
			return Pulled{}, fmt.Errorf("410 without a sealed ended notice: %w", err)
		}
		return Pulled{Ended: &s}, nil
	}
	// 503 is an outage (a desk in restore mode answers it too, KeyClerk 0.25.0): never
	// an ended edge; leases run on their horizons.
	if len(b) > 300 {
		b = b[:300]
	}
	return Pulled{}, &StatusError{Status: status, Body: string(b)}
}

// FetchModule gets a policy module the bundle names by its sha256 and checks the
// bytes against the hash (keyclerk.edge.verify_module).
func (c *Client) FetchModule(ctx context.Context, sha256hex string) ([]byte, error) {
	status, b, err := c.call(ctx, http.MethodGet, "/api/v1/edge/module/"+sha256hex, nil, maxModule)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		if len(b) > 300 {
			b = b[:300]
		}
		return nil, &StatusError{Status: status, Body: string(b)}
	}
	var m struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
		Wasm   string `json:"wasm"`
	}
	if err := json.Unmarshal(b, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("the module answer is not {name, sha256, wasm}: %w", err)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(m.Wasm)
	if err != nil {
		return nil, fmt.Errorf("the module is not base64: %w", err)
	}
	if errs := kcedge.VerifyModule(raw, sha256hex); len(errs) > 0 {
		return nil, fmt.Errorf("module %s: %s", sha256hex[:16], errs[0])
	}
	return raw, nil
}

// Report is what the edge tells the desk after applying (interface section 7).
type Report struct {
	AppliedSerial int64       `json:"applied_serial"`
	Attestation   Attestation `json:"attestation"`
	Drift         []string    `json:"drift"`
}

// Attestation is claimed until quotes are verified (KeyClerk 0016).
type Attestation struct {
	Profile      string `json:"profile"`
	AgentVersion string `json:"agent_version"`
	Mode         string `json:"mode"`
}

// SendReport posts a report.
func (c *Client) SendReport(ctx context.Context, r Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	status, b, err := c.call(ctx, http.MethodPost, "/api/v1/edge/report", body, 64<<10)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &StatusError{Status: status, Body: string(b)}
	}
	return nil
}

// EnrolmentKey is the edge's public enrolment key, the one an ended notice must name (AG-18).
func (c *Client) EnrolmentKey() ed25519.PublicKey { return c.Key.Public().(ed25519.PublicKey) }

// ErrNoLiveLease is the desk's 404 to an e-mail request: the lease is not in the last bundle served, or not live.
var ErrNoLiveLease = errors.New("the desk knows no live lease by that id")

// ErrRateLimited is the desk's 429: more than six e-mail requests a minute for one lease.
var ErrRateLimited = errors.New("the desk limits e-mail requests for this lease: try later")

// Email asks the desk for a lease's verified address (edge protocol 1.3, GET /api/v1/edge/lease/{id}/email). It returns
// the sealed answer and the nonce this request was signed with: the caller verifies both (kcedge.VerifyEmail).
func (c *Client) Email(ctx context.Context, leaseID string) (*kcedge.Sealed, string, error) {
	nonce := kcedge.NewNonce()
	status, b, err := c.callNonce(ctx, c.HTTP, http.MethodGet, "/api/v1/edge/lease/"+url.PathEscape(leaseID)+"/email", nil,
		16<<10, nonce)
	if err != nil {
		return nil, "", err
	}
	switch status {
	case http.StatusOK:
		var s kcedge.Sealed
		if err := json.Unmarshal(b, &s, json.RejectUnknownMembers(true)); err != nil {
			return nil, "", fmt.Errorf("the e-mail answer is not a sealed object: %w", err)
		}
		return &s, nonce, nil
	case http.StatusNotFound:
		return nil, "", ErrNoLiveLease
	case http.StatusTooManyRequests:
		return nil, "", ErrRateLimited
	}
	return nil, "", &StatusError{Status: status, Body: string(b[:min(len(b), 200)])}
}

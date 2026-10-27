// SPDX-License-Identifier: EUPL-1.2

// Package warpgate is the agent's client for Warpgate's admin API on loopback
// (routes under /@warpgate/admin/api, header X-Warpgate-Token). It covers only what
// the agent does: users, SSO and public-key credentials, role assignments with expiry,
// the targets a role reaches, sessions.
package warpgate

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"relikey/agent/internal/httpx"
)

const maxBody = 8 << 20

// Client talks to one Warpgate.
type Client struct {
	Base  string // e.g. https://127.0.0.1:8888/@warpgate/admin/api
	Token string
	HTTP  *http.Client
	// RetryBase is the first backoff for retried requests (default 100ms).
	RetryBase time.Duration
}

type User struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Description string `json:"description"`
}

type Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RoleAssignment struct {
	ID        string     `json:"id"` // the role's id
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
	IsActive  bool       `json:"is_active"`
}

type SSOCredential struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
}

// PublicKeyCredential is an SSH public key a user signs in with (visit leases).
type PublicKeyCredential struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	OpenSSHPublicKey string `json:"openssh_public_key"`
}

// Target is a target as a role lists it; only its id and name matter here.
type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type TargetSession struct {
	TargetID string     `json:"target_id"`
	Started  time.Time  `json:"started"`
	Ended    *time.Time `json:"ended"`
}

type Session struct {
	ID             string          `json:"id"`
	Username       string          `json:"username"`
	UserID         string          `json:"user_id"`
	TargetSessions []TargetSession `json:"target_sessions"`
}

// Error is a refusal from Warpgate.
type Error struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *Error) Error() string {
	return fmt.Sprintf("warpgate %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// NotFound reports a 404.
func NotFound(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Warpgate-Token", c.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// GET, PUT and DELETE are idempotent: retried on a transport error or a 5xx, with
	// jittered backoff inside the caller's deadline. POST is not retried here; the next
	// tick plans again from what is observed.
	attempts := 1
	if method != http.MethodPost {
		attempts = 3
	}
	var last error
	for i := range attempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(last, ctx.Err())
			case <-time.After(c.backoff(i)):
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		b, status, err := c.send(req)
		if err == nil && status < 300 {
			if out == nil || len(b) == 0 {
				return nil
			}
			return json.Unmarshal(b, out)
		}
		if err == nil {
			if len(b) > 300 {
				b = b[:300]
			}
			last = &Error{Method: method, Path: path, Status: status, Body: string(b)}
			if status < 500 {
				return last
			}
		} else {
			last = err
		}
	}
	return last
}

func (c *Client) backoff(attempt int) time.Duration {
	base := c.RetryBase
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	d := base << (attempt - 1)
	return d + time.Duration(rand.Int64N(int64(d)/2+1))
}

func (c *Client) send(req *http.Request) ([]byte, int, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	b, err := httpx.ReadAll(resp.Body, maxBody)
	return b, resp.StatusCode, err
}

func (c *Client) Users(ctx context.Context) (out []User, err error) {
	err = c.do(ctx, http.MethodGet, "/users", nil, &out)
	return out, err
}

func (c *Client) CreateUser(ctx context.Context, username, description string) (u User, err error) {
	err = c.do(ctx, http.MethodPost, "/users", map[string]string{"username": username, "description": description}, &u)
	return u, err
}

func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(id), nil, nil)
}

func (c *Client) Roles(ctx context.Context) (out []Role, err error) {
	err = c.do(ctx, http.MethodGet, "/roles", nil, &out)
	return out, err
}

func (c *Client) UserRoles(ctx context.Context, userID string) (out []RoleAssignment, err error) {
	err = c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/roles", nil, &out)
	return out, err
}

func expiry(t time.Time) map[string]any {
	return map[string]any{"expires_at": t.UTC().Format(time.RFC3339)}
}

// AddUserRole assigns a role; an assignment that already exists (409) is done, and the
// next tick sets its expiry if it differs.
func (c *Client) AddUserRole(ctx context.Context, userID, roleID string, expires time.Time) error {
	err := c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/roles/"+url.PathEscape(roleID), expiry(expires), nil)
	if e, ok := err.(*Error); ok && e.Status == http.StatusConflict {
		return nil
	}
	return err
}

func (c *Client) SetUserRoleExpiry(ctx context.Context, userID, roleID string, expires time.Time) error {
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/roles/"+url.PathEscape(roleID), expiry(expires), nil)
}

func (c *Client) RemoveUserRole(ctx context.Context, userID, roleID string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/roles/"+url.PathEscape(roleID), nil, nil)
}

func (c *Client) SSOCredentials(ctx context.Context, userID string) (out []SSOCredential, err error) {
	err = c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/credentials/sso", nil, &out)
	return out, err
}

func (c *Client) AddSSOCredential(ctx context.Context, userID, provider, email string) error {
	return c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/credentials/sso",
		map[string]string{"provider": provider, "email": email}, nil)
}

func (c *Client) DeleteSSOCredential(ctx context.Context, userID, id string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/credentials/sso/"+url.PathEscape(id), nil, nil)
}

func (c *Client) PublicKeys(ctx context.Context, userID string) (out []PublicKeyCredential, err error) {
	err = c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/credentials/public-keys", nil, &out)
	return out, err
}

func (c *Client) AddPublicKey(ctx context.Context, userID, label, key string) error {
	return c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/credentials/public-keys",
		map[string]string{"label": label, "openssh_public_key": key}, nil)
}

func (c *Client) DeletePublicKey(ctx context.Context, userID, id string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/credentials/public-keys/"+url.PathEscape(id), nil, nil)
}

// RoleTargets lists the targets a role reaches (Warpgate v0.30.0: GET /role/{id}/targets).
func (c *Client) RoleTargets(ctx context.Context, roleID string) (out []Target, err error) {
	err = c.do(ctx, http.MethodGet, "/role/"+url.PathEscape(roleID)+"/targets", nil, &out)
	return out, err
}

// ActiveSessions lists every open session, page by page (at most 100 pages of 500).
func (c *Client) ActiveSessions(ctx context.Context) ([]Session, error) {
	var all []Session
	for offset := 0; offset < 100*500; offset += 500 {
		var page struct {
			Items []Session `json:"items"`
			Total int       `json:"total"`
		}
		q := url.Values{"active_only": {"true"}, "offset": {strconv.Itoa(offset)}, "limit": {"500"}}
		if err := c.do(ctx, http.MethodGet, "/sessions?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if len(page.Items) == 0 || len(all) >= page.Total {
			return all, nil
		}
	}
	return nil, errors.New("more than 50000 open sessions: refusing to plan on a partial list")
}

func (c *Client) TargetRoles(ctx context.Context, targetID string) (out []Role, err error) {
	err = c.do(ctx, http.MethodGet, "/targets/"+url.PathEscape(targetID)+"/roles", nil, &out)
	return out, err
}

func (c *Client) CloseSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/sessions/"+url.PathEscape(id)+"/close", nil, nil)
}

// Parameters is the part of Warpgate's global parameters the agent enforces.
type Parameters struct {
	AllowOwnCredentialManagement bool   `json:"allow_own_credential_management"`
	SSHClientAuthPassword        bool   `json:"ssh_client_auth_password"`
	MaxAPITokenDurationSeconds   *int64 `json:"max_api_token_duration_seconds"`
}

func (c *Client) Parameters(ctx context.Context) (out Parameters, err error) {
	err = c.do(ctx, http.MethodGet, "/parameters", nil, &out)
	return out, err
}

// SetParameters changes only the fields given (Warpgate's update takes each one as optional).
func (c *Client) SetParameters(ctx context.Context, in map[string]any) error {
	return c.do(ctx, http.MethodPut, "/parameters", in, nil)
}

// SPDX-License-Identifier: EUPL-1.2

package warpgate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TargetSpec is one target of an edge's targets file (deploy/edge/targets.yaml): the role a lease names, the SSH
// target and its host key, verified out of band.
type TargetSpec struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	SSH     SSH    `json:"ssh"`
	HostKey string `json:"host_key"`
}

// SSH is where Warpgate reaches a target, and as which account.
type SSH struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}

type knownHost struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	KeyType   string `json:"key_type"`
	KeyBase64 string `json:"key_base64"`
}

// CheckTargets refuses a file with a target that lacks a field; a target without host_key is refused because Warpgate
// would trust whatever key answers first (full-stack run, 2026-10-24).
func CheckTargets(specs []TargetSpec) error {
	var problems []string
	for _, t := range specs {
		name := t.Name
		if name == "" {
			name = "?"
		}
		for k, v := range map[string]string{"name": t.Name, "role": t.Role, "ssh.host": t.SSH.Host,
			"ssh.username": t.SSH.Username, "host_key": t.HostKey} {
			if v == "" {
				p := fmt.Sprintf("target %s: %s is missing", name, k)
				if k == "host_key" {
					p += " (the target's host key, verified out of band; no trust on first use)"
				}
				problems = append(problems, p)
			}
		}
		if t.HostKey != "" && len(strings.Fields(t.HostKey)) < 2 {
			problems = append(problems, fmt.Sprintf("target %s: host_key is not \"TYPE BASE64\" (as ssh-keyscan prints it)", name))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("refused, nothing changed:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// ApplyTargets makes Warpgate hold the edge's targets: each role a lease names, each target (updated to the file
// when it exists), the role bound to it, and its pinned host key. It reports each change on out and returns
// Warpgate's own SSH client keys, which go into each target account's authorized_keys. Idempotent. This is the
// installation's part ("the installation creates roles and binds them to targets"); the agent's loop only assigns
// roles from signed leases.
func (c *Client) ApplyTargets(ctx context.Context, specs []TargetSpec, out io.Writer) ([]string, error) {
	if err := CheckTargets(specs); err != nil {
		return nil, err
	}
	var rs []Role
	if err := c.do(ctx, http.MethodGet, "/roles", nil, &rs); err != nil {
		return nil, err
	}
	roles := map[string]string{}
	for _, r := range rs {
		roles[r.Name] = r.ID
	}
	var ts []Target
	if err := c.do(ctx, http.MethodGet, "/targets", nil, &ts); err != nil {
		return nil, err
	}
	targets := map[string]string{}
	for _, t := range ts {
		targets[t.Name] = t.ID
	}
	var kh []knownHost
	if err := c.do(ctx, http.MethodGet, "/ssh/known-hosts", nil, &kh); err != nil {
		return nil, err
	}
	known := map[knownHost]bool{}
	for _, k := range kh {
		known[k] = true
	}
	for _, t := range specs {
		port := t.SSH.Port
		if port == 0 {
			port = 22
		}
		if _, ok := roles[t.Role]; !ok {
			var r Role
			if err := c.do(ctx, http.MethodPost, "/roles",
				map[string]string{"name": t.Role, "description": "lease role for " + t.Name}, &r); err != nil {
				return nil, err
			}
			roles[t.Role] = r.ID
			fmt.Fprintf(out, "role %s: created\n", t.Role)
		}
		body := map[string]any{"name": t.Name, "ticket_requests_disabled": true, "ticket_require_approval": false,
			"require_approval": false,
			"options": map[string]any{"kind": "Ssh", "host": t.SSH.Host, "port": port, "username": t.SSH.Username,
				"allow_insecure_algos": false, "auth": map[string]string{"kind": "PublicKey"}}}
		tid, ok := targets[t.Name]
		if ok {
			if err := c.do(ctx, http.MethodPut, "/targets/"+url.PathEscape(tid), body, nil); err != nil {
				return nil, err
			}
			fmt.Fprintf(out, "target %s: kept (updated to the file)\n", t.Name)
		} else {
			var created Target
			if err := c.do(ctx, http.MethodPost, "/targets", body, &created); err != nil {
				return nil, err
			}
			tid = created.ID
			targets[t.Name] = tid
			fmt.Fprintf(out, "target %s: created (%s@%s:%d)\n", t.Name, t.SSH.Username, t.SSH.Host, port)
		}
		bound, err := c.TargetRoles(ctx, tid)
		if err != nil {
			return nil, err
		}
		has := false
		for _, r := range bound {
			has = has || r.Name == t.Role
		}
		if !has {
			if err := c.do(ctx, http.MethodPost, "/targets/"+url.PathEscape(tid)+"/roles/"+url.PathEscape(roles[t.Role]),
				nil, nil); err != nil {
				return nil, err
			}
			fmt.Fprintf(out, "target %s: role %s bound\n", t.Name, t.Role)
		}
		f := strings.Fields(t.HostKey)
		k := knownHost{Host: t.SSH.Host, Port: port, KeyType: f[0], KeyBase64: f[1]}
		if !known[k] {
			if err := c.do(ctx, http.MethodPost, "/ssh/known-hosts", k, nil); err != nil {
				return nil, err
			}
			known[k] = true
			fmt.Fprintf(out, "target %s: host key pinned (%s)\n", t.Name, k.KeyType)
		}
	}
	var own []struct {
		PublicKey string `json:"public_key"`
	}
	if err := c.do(ctx, http.MethodGet, "/ssh/own-keys", nil, &own); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(own))
	for _, k := range own {
		keys = append(keys, k.PublicKey)
	}
	return keys, nil
}

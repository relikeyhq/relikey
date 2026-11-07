// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"relikey/agent/internal/httpx"
	"relikey/agent/internal/warpgate"
)

// targetsFile is what deploy/edge/targets.py hands over: its targets.yaml, checked and as JSON.
type targetsFile struct {
	Targets []warpgate.TargetSpec `json:"targets"`
}

// targets applies the edge's targets to the bastion with the agent's own configuration: its loopback URL, pinned
// certificate and token file. It runs where the agent runs, in the pod's network namespace, so the bastion's admin
// API stays on loopback (decision 0008); deploy/edge/targets.py runs it with `compose exec` (walk 2026-11-06, F14).
func targets(args []string) error {
	fs := flag.NewFlagSet("targets", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/relikey/agent.json", "configuration file")
	in := fs.String("in", "-", "the targets as JSON, as deploy/edge/targets.py sends them; - for standard input")
	_ = fs.Parse(args)
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	var r io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	specs, err := readTargets(r)
	if err != nil {
		return err
	}
	token, err := readSecret(c.Bastion.TokenFile)
	if err != nil {
		return err
	}
	h, err := bastionHTTP(c, &httpx.Group{})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	wg := &warpgate.Client{Base: strings.TrimRight(c.Bastion.URL, "/"), Token: token, HTTP: h}
	keys, err := wg.ApplyTargets(ctx, specs, os.Stdout)
	if err != nil {
		return fmt.Errorf("%w; what is listed above was applied, the rest was not: fix it and run it again "+
			"(it is idempotent)", err)
	}
	printClientKeys(os.Stdout, keys)
	return nil
}

func readTargets(r io.Reader) ([]warpgate.TargetSpec, error) {
	var f targetsFile
	if err := json.UnmarshalRead(r, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("the targets: %w; give them as deploy/edge/targets.py does", err)
	}
	if len(f.Targets) == 0 {
		return nil, fmt.Errorf("the targets list is empty: nothing to apply (deploy/edge/targets.example.yaml shows one)")
	}
	return f.Targets, warpgate.CheckTargets(f.Targets)
}

// printClientKeys prints the bastion's own SSH keys as authorized_keys lines. restrict: the lease reaches the
// target's shell, not what the target can reach (no -L/-D/-R, no agent or X11 forwarding: stack attack 2026-10-25,
// E9); pty keeps an interactive shell.
func printClientKeys(w io.Writer, keys []string) {
	fmt.Fprintln(w, "\nWarpgate's client keys - put them in each SSH target account's authorized_keys:")
	for _, k := range keys {
		fmt.Fprintln(w, "  restrict,pty "+k)
	}
}

// SPDX-License-Identifier: EUPL-1.2

// Command relikey-agent is the ReliKey edge agent (decision 0011): it verifies what
// KeyClerk signed and makes Warpgate hold exactly what the live leases allow.
//
//	relikey-agent run    -config agent.json    the loop (mode enforce or shadow)
//	relikey-agent plan   -config agent.json    one reconcile in shadow, the plan as JSON
//	relikey-agent status -file status.json [-max-streak N] [-max-age 2m]
//	                                           print the status; exit 1 when unhealthy (canary gate)
//	relikey-agent keygen -out enrolment.key    a new enrolment key (0600), prints the public key
//	relikey-agent pin    -cert warpgate.pem    the SHA-256 pin of a certificate
//	relikey-agent version
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"relikey/agent/internal/agent"
	"relikey/agent/internal/apply"
	"relikey/agent/internal/clock"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/keyclerk"
	"relikey/agent/internal/state"
	"relikey/agent/internal/warpgate"
	"relikey/agent/pkg/fleetproto"
)

// version is set at release builds (-ldflags "-X main.version=...").
var version = "dev"

// Config is agent.json. Unknown keys are refused: a misspelt setting must not
// silently fall back to a default.
//
// Every field carries a comment: docs/reference/agent-config.md is generated from
// them (tools/docs.py), and the docs check fails on a field without one.
type Config struct {
	// Required. The edge's id as KeyClerk enrolled it; bundles for another edge are refused.
	Edge string `json:"edge"`
	// enforce (default) applies the plan to the bastion; shadow only computes and reports it (the canary).
	Mode agent.Mode `json:"mode"`
	// Required. Where the verified bundle, floors and status files live; must be the agent's own, persistent directory.
	StateDir string `json:"state_dir"`
	// Allows a volatile or shared state directory and a non-loopback bastion: tests and the soak only, never a site.
	Lab bool `json:"lab"`
	// Required. The edge's enrolment key (relikey-agent keygen), mode 0600, owned by the agent's user.
	EnrolmentKeyFile string `json:"enrolment_key_file"`
	// The keys the edge trusts, pinned on site at enrolment; never fetched from the network.
	Pins struct {
		// Required. KeyClerk's bundle signing key (hex), from the enrolment.
		BundleKey string `json:"bundle_key"`
		// Required. The edge officer's key (hex), from the officer's own console; it seals the edge's ceiling.
		OfficerKey string `json:"officer_key"`
		// Optional. KeyClerk's release key (hex); with it, policy modules must be the ones its signed manifest names.
		ReleaseKey *string `json:"release_key"`
	} `json:"pins"`
	// The clerk role (decision 0023): how the agent reaches the clerk's edge routes, which speak the edge protocol
	// (outbound only; the core never connects in). KeyClerk is the reference clerk.
	Clerk struct {
		// Required. The desk's edge-facing base URL, https.
		URL string `json:"url"`
		// Optional. A PEM file with the CA that signs the desk's certificate, when it is not a public one.
		CAFile string `json:"ca_file"`
		// Optional. The sha256 of the desk certificate's public key; with it, any other certificate is refused.
		PinSHA256 string `json:"pin_sha256"`
		// Optional. An http(s) proxy for the outbound connection to the desk.
		Proxy string `json:"proxy"`
	} `json:"clerk"`
	// The bastion role (decision 0023): which bastion the agent drives and how it reaches its admin API on the edge's
	// loopback (decision 0008).
	Bastion struct {
		// Required. The bastion's adapter: warpgate (the reference bastion). Any other value is refused.
		Kind string `json:"kind"`
		// Required. https on 127.0.0.1 or [::1], with the admin API path (Warpgate: /@warpgate/admin/api).
		URL string `json:"url"`
		// Required. A file holding the bastion's admin token, mode 0600.
		TokenFile string `json:"token_file"`
		// Required. The sha256 of the bastion's certificate public key (relikey-agent pin).
		PinSHA256 string `json:"pin_sha256"`
		// Required. The name of the bastion's single sign-on provider for the core broker (decision 0010).
		SSOProvider string `json:"sso_provider"`
		// Optional. A SCIM list of the roles only leases grant (deploy/edge/targets.py writes it from the edge's targets
		// file): an account the agent does not manage holding one is reported in the drift, never changed. Read every
		// tick; absent, unmanaged accounts are not checked (full-stack run 2, finding 8).
		GovernedRolesFile string `json:"governed_roles_file"`
	} `json:"bastion"`
	// Optional: ReliKey's fleet service (decision 0026). The agent sends its signed report to url/fleet/v1/report every
	// pull interval; url must be the clerk's own scheme and host (the front's edge-facing name), so the same pinned,
	// hybrid-only client carries it. Absent: no reports.
	Fleet struct {
		// Optional. https on the clerk's own host: the fleet service's report route, behind the front (decision 0026).
		URL string `json:"url"`
	} `json:"fleet"`
	// How often the agent reconciles the bastion with the live leases, in seconds (default 15).
	TickSeconds int `json:"tick_seconds"`
	// How often the agent pulls a bundle from the desk, in seconds (default 60).
	PullSeconds int `json:"pull_seconds"`
	// How long the desk may hold a pull until the edge's bundle changes, in seconds (KeyClerk decision 0026): 0 is the
	// default 55, at most 55, -1 pulls plainly. A desk without long-poll answers at once, and the agent falls back to
	// pull_seconds.
	LongPollSeconds int `json:"long_poll_seconds"`
	// How long removals may still run after a shutdown signal, in seconds (default 5); keep it below the stop timeout.
	GraceSeconds int `json:"grace_seconds"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = run(args, false)
	case "plan":
		err = run(args, true)
	case "status":
		err = status(args)
	case "keygen":
		err = keygen(args)
	case "pin":
		err = pin(args)
	case "statement":
		err = statementShow(args)
	case "cosign":
		err = cosign(args)
	case "unlock-keygen":
		err = unlockKeygen(args)
	case "unlock-code":
		err = unlockCode(args)
	case "version":
		fmt.Println(versionString())
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "relikey-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relikey-agent run|plan|status|keygen|pin|statement|cosign|unlock-keygen|unlock-code|version [flags]")
	os.Exit(2)
}

// releaseString is the bare version for the fleet report: the build's version, and on a development build the
// commit, so two builds are told apart ("dev-26734a855cd6").
func releaseString() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "vcs.revision" && len(kv.Value) >= 12 {
				return "dev-" + kv.Value[:12]
			}
		}
	}
	return "dev"
}

func versionString() string {
	s := "relikey-agent " + version
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "vcs.revision" && len(kv.Value) >= 12 {
				s += " " + kv.Value[:12]
			}
			if kv.Key == "vcs.modified" && kv.Value == "true" {
				s += "+dirty"
			}
		}
		s += " " + bi.GoVersion
	}
	return s
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top map[string]jsontext.Value
	if json.Unmarshal(b, &top) == nil {
		if _, old := top["keyclerk"]; old {
			return nil, fmt.Errorf("%s: the \"keyclerk\" section is now \"clerk\" (decision 0023, configuration by role): rename it", path)
		}
		if _, old := top["warpgate"]; old {
			return nil, fmt.Errorf("%s: the \"warpgate\" section is now \"bastion\" with \"kind\": \"warpgate\" (decision 0023, "+
				"configuration by role): rename it and add the kind", path)
		}
	}
	var c Config
	if err := json.Unmarshal(b, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var missing []string
	for k, v := range map[string]string{"edge": c.Edge, "state_dir": c.StateDir, "enrolment_key_file": c.EnrolmentKeyFile,
		"pins.bundle_key": c.Pins.BundleKey, "pins.officer_key": c.Pins.OfficerKey, "clerk.url": c.Clerk.URL,
		"bastion.kind": c.Bastion.Kind, "bastion.url": c.Bastion.URL, "bastion.token_file": c.Bastion.TokenFile,
		"bastion.pin_sha256": c.Bastion.PinSHA256, "bastion.sso_provider": c.Bastion.SSOProvider} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s: missing %s", path, strings.Join(missing, ", "))
	}
	if c.Mode == "" {
		c.Mode = agent.Enforce
	}
	// The admin API is reached on loopback only (decision 0008), by a literal address:
	// "localhost" can resolve elsewhere, and a scratch image has no /etc/hosts (AG-19).
	if c.Bastion.Kind != "warpgate" {
		return nil, fmt.Errorf("bastion.kind %q: this agent has the warpgate adapter only (decision 0023); "+
			"another bastion needs its adapter first", c.Bastion.Kind)
	}
	if u, err := url.Parse(c.Bastion.URL); err != nil || u.Scheme != "https" ||
		(!c.Lab && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		return nil, fmt.Errorf("bastion.url %q: https on 127.0.0.1 or [::1] (the bastion's admin API is loopback only)", c.Bastion.URL)
	}
	if c.Mode != agent.Enforce && c.Mode != agent.Shadow {
		return nil, fmt.Errorf("mode %q: enforce or shadow", c.Mode)
	}
	for _, k := range []string{c.Pins.BundleKey, c.Pins.OfficerKey} {
		if _, err := kcedge.PublicKey(k); err != nil {
			return nil, fmt.Errorf("pins: %w", err)
		}
	}
	return &c, nil
}

// readSecret reads a key or token file and refuses one others can read.
func readSecret(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if secretTooOpen(fi.Mode()) {
		return "", fmt.Errorf("%s is %v: make it 0600, owned by the agent's user", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

func run(args []string, once bool) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/relikey/agent.json", "configuration file")
	_ = fs.Parse(args)
	harden()
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	seedHex, err := readSecret(c.EnrolmentKeyFile)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s: an Ed25519 seed is 64 hex characters", c.EnrolmentKeyFile)
	}
	token, err := readSecret(c.Bastion.TokenFile)
	if err != nil {
		return err
	}
	// Both links have ReliKey at both ends (the core's front, the edge's bastion on loopback): hybrid post-quantum key
	// exchange is required, and a peer without it is refused (decision 0022 A3; model/crypto.yaml F-06, F-07).
	clerkTLS, bastionTLS := &httpx.Group{}, &httpx.Group{}
	kcOpts := httpx.Options{Timeout: 30 * time.Second, MinTLS13: true, PinSHA256: c.Clerk.PinSHA256,
		RequireHybrid: true, Group: clerkTLS}
	if c.Clerk.CAFile != "" {
		pemBytes, err := os.ReadFile(c.Clerk.CAFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return fmt.Errorf("%s holds no certificate", c.Clerk.CAFile)
		}
		kcOpts.RootCAs = pool
	}
	if c.Clerk.Proxy != "" {
		if kcOpts.Proxy, err = url.Parse(c.Clerk.Proxy); err != nil {
			return err
		}
	}
	kcHTTP, err := httpx.New(kcOpts)
	if err != nil {
		return fmt.Errorf("clerk: %w", err)
	}
	pollOpts := kcOpts // the same pin, TLS and proxy; timeouts above the desk's 55 s hold
	pollOpts.Timeout, pollOpts.ResponseHeader = 75*time.Second, 70*time.Second
	pollHTTP, err := httpx.New(pollOpts)
	if err != nil {
		return fmt.Errorf("clerk: %w", err)
	}
	wait := 55 * time.Second
	switch {
	case c.LongPollSeconds < 0:
		wait = 0
	case c.LongPollSeconds > 55:
		return errors.New("long_poll_seconds: at most 55 (the desk's longest hold), 0 for the default, -1 for plain pulls")
	case c.LongPollSeconds > 0:
		wait = time.Duration(c.LongPollSeconds) * time.Second
	}
	wgHTTP, err := httpx.New(httpx.Options{Timeout: 20 * time.Second, PinSHA256: c.Bastion.PinSHA256,
		RequireHybrid: true, Group: bastionTLS})
	if err != nil {
		return fmt.Errorf("bastion: %w", err)
	}
	store, err := state.Open(c.StateDir, c.Lab)
	if err != nil {
		return err
	}
	defer store.Close()
	clk := clock.System{}
	if c.Mode == agent.Enforce && !c.Lab && clk.BootID() == "" {
		// Without a boot id the agent cannot tell a reboot from a wall clock set back, so an
		// expired lease could come back (AG-3).
		return errors.New("enforce mode needs the kernel's boot id (/proc/sys/kernel/random/boot_id): " +
			"run on Linux with /proc mounted, or use shadow mode")
	}
	a := &agent.Agent{
		Pins:     kcedge.Pins{Edge: c.Edge, BundleKey: c.Pins.BundleKey, OfficerKey: c.Pins.OfficerKey, ReleaseKey: c.Pins.ReleaseKey},
		Provider: c.Bastion.SSOProvider, Mode: c.Mode, Version: versionString(), Release: releaseString(), Store: store, Clock: clk, Log: log,
		// The composition root is the one place that names products: the clerk speaks the edge protocol (KeyClerk is the
		// reference clerk), the bastion is the Warpgate adapter (bastion.kind checked above).
		Clerk: &keyclerk.Client{Base: strings.TrimRight(c.Clerk.URL, "/"), Edge: c.Edge,
			Key: ed25519.NewKeyFromSeed(seed), HTTP: kcHTTP, PollHTTP: pollHTTP, Now: clk.Now},
		Bastion:  warpgate.Bastion{C: &warpgate.Client{Base: strings.TrimRight(c.Bastion.URL, "/"), Token: token, HTTP: wgHTTP}},
		ClerkTLS: clerkTLS, BastionTLS: bastionTLS,
		Tick: time.Duration(c.TickSeconds) * time.Second, Pull: time.Duration(c.PullSeconds) * time.Second,
		Grace: time.Duration(c.GraceSeconds) * time.Second, Wait: wait,
	}
	a.Events = os.Stdout // chained JSON lines beside the log, told apart by "specversion" (decision 0025)
	if c.Fleet.URL != "" {
		fu, ferr := url.Parse(c.Fleet.URL)
		cu, _ := url.Parse(c.Clerk.URL)
		if ferr != nil || fu.Scheme != "https" || cu == nil || fu.Host != cu.Host || fu.User != nil ||
			(fu.Path != "" && fu.Path != "/") || fu.RawQuery != "" || fu.Fragment != "" {
			return fmt.Errorf("fleet.url: https://<the clerk's own host>, no path, query or user (%s)", c.Clerk.URL)
		}
		a.Fleet = &fleetproto.Client{URL: c.Fleet.URL, HTTP: kcHTTP, Key: ed25519.NewKeyFromSeed(seed)}
	}
	if f := c.Bastion.GovernedRolesFile; f != "" {
		a.Governed = func() (map[string]bool, error) {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			return apply.ParseGoverned(b)
		}
	}
	if once {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		p, err := a.Once(ctx)
		if err != nil {
			return err
		}
		out, _ := json.Marshal(p, json.Deterministic(true))
		fmt.Println(string(out))
		return nil
	}
	// The first SIGTERM/SIGINT stops the loop (removals finish within the grace, no
	// grant starts); stop() restores the default, so a second signal exits at once.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	return a.Run(ctx)
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	file := fs.String("file", "/var/lib/relikey/status.json", "the agent's status.json")
	maxStreak := fs.Int("max-streak", 2, "unhealthy when this many ticks in a row end with a plan left over")
	maxAge := fs.Duration("max-age", 2*time.Minute, "unhealthy when the status is older than this")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var st agent.Status
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	fmt.Println(string(b))
	if bad := st.Health(time.Now(), *maxStreak, *maxAge); len(bad) > 0 {
		return errors.New("unhealthy: " + strings.Join(bad, "; "))
	}
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file for the new enrolment key (must not exist)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("keygen -out FILE")
	}
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	// Created 0600 from the start and never over an existing key: a key edges pinned
	// must be restored, not replaced (KeyClerk red team H7).
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fmt.Printf("enrolment key %s\nkey id %s\n", hex.EncodeToString(pub), kcedge.KeyID(hex.EncodeToString(pub)))
	return nil
}

func pin(args []string) error {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	cert := fs.String("cert", "", "a PEM certificate file")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*cert)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("%s holds no PEM certificate", *cert)
	}
	fmt.Println(httpx.CertSHA256(blk.Bytes))
	return nil
}

// SPDX-License-Identifier: EUPL-1.2

// Command relikey-fleet is ReliKey's fleet service (decision 0026): it receives each edge's signed report through the
// front and keeps the inventory and the silence alarm. It listens on loopback only; the front routes the edge-facing
// name's /fleet/ paths to it (model F-27, F-28).
//
//	relikey-fleet -config /etc/relikey/fleet.json
//	relikey-fleet -version
//
// fleet.json: {"listen": "127.0.0.1:8093", "state": "/var/lib/relikey-fleet/fleet.json", "silence_seconds": 300,
// "edges": {"plant-a": "<the edge's enrolment public key, 64 hex>"}}. Without a clerk the known edges come from here;
// with one, from the clerk's enrolled edges (later).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"relikey/agent/pkg/events"
	"relikey/fleet/internal/fleet"
	"relikey/fleet/internal/page"
)

// version is set at release builds (-ldflags "-X main.version=...").
var version = "dev"

// versionString names the build as the agent's does: version, commit and Go release, so a release's smoke test can
// check the binary is the tagged one.
func versionString() string {
	s := "relikey-fleet " + version
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

type config struct {
	Listen         string            `json:"listen"`
	State          string            `json:"state"`
	SilenceSeconds int               `json:"silence_seconds"`
	Edges          map[string]string `json:"edges"`
	Page           *page.Config      `json:"page,omitempty"` // the fleet page (0026 point 13); absent: no page
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

func load(path string) (config, map[string]ed25519.PublicKey, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, nil, fmt.Errorf("%s: %w", path, err)
	}
	if !loopback(c.Listen) {
		return c, nil, errors.New("listen: a loopback address and port, e.g. 127.0.0.1:8093 (the front is the only way in)")
	}
	if p := c.Page; p != nil {
		switch {
		case !loopback(p.Listen) || p.Listen == c.Listen:
			return c, nil, errors.New("page.listen: a loopback address and port of its own, e.g. 127.0.0.1:8094 (the front proxies the page's routes to it)")
		case p.Issuer == "" || p.ClientID == "" || p.SecretFile == "" || p.RedirectURL == "" || p.CAFile == "":
			return c, nil, errors.New("page: issuer, client_id, secret_file, redirect_url and ca_file are all needed (the fleet's client at the broker; deploy/core/fleet_page.py writes them)")
		case p.Role == "":
			p.Role = "fleet-operator"
		}
	}
	if c.State == "" {
		return c, nil, errors.New("state: the inventory file's path is missing, e.g. /var/lib/relikey-fleet/fleet.json " +
			"(deploy/core/install.py writes it)")
	}
	if c.SilenceSeconds <= 0 {
		c.SilenceSeconds = 300
	}
	keys := map[string]ed25519.PublicKey{}
	for edge, h := range c.Edges {
		k, err := hex.DecodeString(h)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return c, nil, fmt.Errorf("edges.%s: not an Ed25519 public key of 64 hex characters; write the edge's "+
				"enrolment key again with deploy/core/fleet_edge.py --edge %s --key <key>", edge, edge)
		}
		keys[edge] = ed25519.PublicKey(k)
	}
	return c, keys, nil
}

func main() {
	path := flag.String("config", "/etc/relikey/fleet.json", "the fleet service's configuration")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionString())
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	c, keys, err := load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relikey-fleet:", err)
		os.Exit(2)
	}
	known := make([]string, 0, len(keys))
	for e := range keys {
		known = append(known, e)
	}
	inv, err := fleet.Open(c.State, known, time.Duration(c.SilenceSeconds)*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relikey-fleet:", err)
		os.Exit(1)
	}
	s := &fleet.Server{Inv: inv, Keys: keys, Now: time.Now, Log: log, Emit: (&events.Writer{W: os.Stdout}).Emit}
	srv := &http.Server{Addr: c.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go s.Watch(15*time.Second, done)
	go func() {
		<-ctx.Done()
		close(done)
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if c.Page != nil {
		secret, err := page.ReadSecret(os.ReadFile, c.Page.SecretFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "relikey-fleet: page.secret_file:", err)
			os.Exit(2)
		}
		hc, err := page.Client(*c.Page, os.ReadFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "relikey-fleet: page:", err)
			os.Exit(2)
		}
		pg, err := page.New(page.WithClient(ctx, hc), *c.Page, secret, func() (string, any) {
			return "self-reported, not attested (no clerk facts yet)", inv.View()
		}, log)
		if err != nil { // the broker is not reachable yet: the inventory runs, the page says why it is missing
			log.Error("fleet page not started", "err", err, "next", "check page.issuer and that the broker is up, then restart the fleet service")
		} else {
			pg.HTTP = hc
			psrv := &http.Server{Addr: c.Page.Listen, Handler: pg.Handler(), ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second}
			go func() { <-ctx.Done(); _ = psrv.Close() }()
			go func() {
				if err := psrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error("fleet page stopped", "err", err)
				}
			}()
			log.Info("fleet page started", "listen", c.Page.Listen, "issuer", c.Page.Issuer)
		}
	}
	log.Info("fleet service started", "listen", c.Listen, "edges", len(keys), "silence_seconds", c.SilenceSeconds)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "relikey-fleet:", err)
		os.Exit(1)
	}
}

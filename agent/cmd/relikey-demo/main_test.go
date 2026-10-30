// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestStory plays the whole demo headless and checks that every step of the story happened, in order.
func TestStory(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "relikey-demo-*"))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var out bytes.Buffer
	s := &Story{}
	if err := Run(ctx, s, Options{Out: &out}); err != nil {
		t.Fatalf("the story stopped: %v\nsteps: %s", err, out.String())
	}
	var keys []string
	for _, st := range s.Steps() {
		keys = append(keys, st.Key)
	}
	want := []string{"started", "signed-in", "lease-granted", "lease-applied", "session-allowed", "lease-revoked",
		"access-removed", "desk-offline", "lease-ended-offline", "done"}
	if !slices.Equal(keys, want) {
		t.Fatalf("steps %v, want %v", keys, want)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("%d JSON lines, want %d", len(lines), len(want))
	}
	for _, l := range lines {
		var st Step
		if err := json.Unmarshal([]byte(l), &st); err != nil || st.Key == "" {
			t.Fatalf("not a step line: %q (%v)", l, err)
		}
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "relikey-demo-*"))
	if len(after) > len(before) {
		t.Fatalf("the demo left its temporary directory behind: %v", after)
	}
}

// TestPageSaysDemo: the page and the story route both carry the demo label, and the page forbids inline script.
func TestPageSaysDemo(t *testing.T) {
	srv := httptest.NewServer((&Story{}).handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	if !strings.Contains(b.String(), "DEMO:") || !strings.Contains(b.String(), "<title>ReliKey demo</title>") {
		t.Fatal("the page does not say it is a demo")
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("policy %q", csp)
	}
	r2, err := http.Get(srv.URL + "/api/story")
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatal(r2.Status)
	}
}

// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A broker that answers only on the third try still gets the page started, with each miss logged and what to check
// (walk 2026-11-06, F9: the page stayed down until someone restarted the fleet).
func TestThePageStartsOnceTheBrokerAnswers(t *testing.T) {
	var buf bytes.Buffer
	tries := 0
	retryStart(context.Background(), func() error {
		if tries++; tries < 3 {
			return errors.New("issuer: 502 Bad Gateway")
		}
		return nil
	}, slog.New(slog.NewTextHandler(&buf, nil)), time.Millisecond, 4*time.Millisecond)
	if tries != 3 {
		t.Fatalf("%d tries, want 3", tries)
	}
	if n := strings.Count(buf.String(), "fleet page not started yet"); n != 2 || !strings.Contains(buf.String(), "page.issuer") {
		t.Fatalf("%d warnings, want 2 naming page.issuer:\n%s", n, buf.String())
	}
}

// Shutting down ends the retries.
func TestRetriesEndWithTheService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		retryStart(ctx, func() error { return errors.New("down") }, slog.New(slog.DiscardHandler), time.Millisecond, time.Millisecond)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("still retrying after shutdown")
	}
}

// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMain lets a test run the demo's own main in a child process (RELIKEY_DEMO_RUN_MAIN=1), so the address rule is
// checked as a person would meet it.
func TestMain(m *testing.M) {
	if os.Getenv("RELIKEY_DEMO_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Outside the demo image the page never listens beyond loopback: not with -addr 0.0.0.0, and not with the image's
// variable set either, since the demo is not the container's first process.
func TestThePageStaysOnLoopbackOutsideTheImage(t *testing.T) {
	for _, env := range [][]string{nil, {"RELIKEY_DEMO_CONTAINER=1"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // a demo that listens never exits
		cmd := exec.CommandContext(ctx, os.Args[0], "-addr", "0.0.0.0:0", "-no-open")
		cmd.Env = append(append(os.Environ(), "RELIKEY_DEMO_RUN_MAIN=1"), env...)
		out, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "must be a loopback address") {
			t.Fatalf("env %v: err %v, output %q: want a refusal (exit 2)", env, err, out)
		}
	}
}

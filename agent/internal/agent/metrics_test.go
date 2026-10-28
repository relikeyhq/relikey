// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/fakes"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// The copy replaces the previous one whole, other users can read it, and no temporary file is left for a collector
// to read.
func TestTheMetricsCopyIsWholeAndReadableByOthers(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"relikey_agent_healthy 0\nrelikey_agent_ticks 1\n", "relikey_agent_healthy 1\n"} {
		if err := WriteMetricsDir(dir, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, MetricsFile)); string(got) != body {
			t.Fatalf("the copy holds %q, want %q", got, body)
		}
	}
	if got := names(t, dir); len(got) != 1 || got[0] != MetricsFile {
		t.Fatalf("the directory holds %v, want only %s", got, MetricsFile)
	}
	if runtime.GOOS == "windows" {
		return // no Unix modes there
	}
	fi, _ := os.Stat(filepath.Join(dir, MetricsFile))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("the copy is %v, want 0644 so the collector's user can read it", fi.Mode().Perm())
	}
}

// A copy that cannot be put in place leaves no temporary file, and its error names the cause without the temporary
// file's random name, so a lasting cause logs once.
func TestAFailedMetricsCopyLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, MetricsFile, "x"), 0o755); err != nil { // the name is taken by a directory
		t.Fatal(err)
	}
	err := WriteMetricsDir(dir, []byte("relikey_agent_healthy 1\n"))
	if err == nil || !strings.Contains(err.Error(), "writing "+MetricsFile) || strings.Contains(err.Error(), ".tmp") {
		t.Fatalf("got %v, want a failure naming %s and not the temporary file", err, MetricsFile)
	}
	if got := names(t, dir); len(got) != 1 {
		t.Fatalf("the directory holds %v: a temporary file was left behind", got)
	}
}

// A directory the agent cannot write keeps the previous copy as it was.
func TestAnUnwritableMetricsDirKeepsThePreviousCopy(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix modes and a user that is not root")
	}
	dir := t.TempDir()
	if err := WriteMetricsDir(dir, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	err := WriteMetricsDir(dir, []byte("new\n"))
	if err == nil || !strings.Contains(err.Error(), "make it writable by the agent's user") {
		t.Fatalf("got %v, want a failure saying what to change", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, MetricsFile)); string(got) != "old\n" {
		t.Fatalf("the previous copy became %q", got)
	}
}

// A missing metrics directory never stops the agent: leases are applied, the status says why the copy failed and
// what to do, and once the directory exists the copy is the same as metrics.prom in the state directory.
func TestAMissingMetricsDirNeverStopsTheAgent(t *testing.T) {
	mdir := filepath.Join(t.TempDir(), "metrics")
	r := newRigTuned(t, func(a *Agent) { a.MetricsDir = mdir })
	r.kc.SetLeases([]fakes.FakeLease{lease("L-1", time.Now().Add(time.Hour))}, nil)
	r.eventually("ann gets the role", func() bool { _, ok := r.roles("ann")["plc-operator"]; return ok })
	r.eventually("the status says why the copy fails", func() bool {
		st := r.status()
		return strings.Contains(st.MetricsDirError, "does not exist: create it") && st.MetricsDirFailures > 0
	})
	if err := os.Mkdir(mdir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.eventually("the copy is written and the error cleared", func() bool {
		_, err := os.Stat(filepath.Join(mdir, MetricsFile))
		return err == nil && r.status().MetricsDirError == ""
	})
	r.halt()
	copied, _ := os.ReadFile(filepath.Join(mdir, MetricsFile))
	own, _ := os.ReadFile(filepath.Join(r.dir, "metrics.prom"))
	if len(own) == 0 || !bytes.Equal(copied, own) {
		t.Fatalf("the copy differs from metrics.prom:\n%s\n---\n%s", copied, own)
	}
	if !bytes.Contains(copied, []byte("relikey_agent_metrics_dir_failures_total ")) {
		t.Error("the copy does not count the failed copies")
	}
}

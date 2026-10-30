// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// MetricsFile is the copy's name in metrics_dir; a textfile collector reads the *.prom files there.
const MetricsFile = "relikey-agent.prom"

// Metrics is the status as Prometheus text exposition, written to metrics.prom beside
// status.json when the status changes and at the heartbeat (Agent.StatusHeartbeat, a minute), so
// relikey_agent_status_updated_seconds tells a live agent from a stalled one; the runtime gauges
// are as of that write. The agent serves nothing, so it is read by a textfile
// collector (node_exporter --collector.textfile.directory) or copied out; the names and
// the status-only health follow KeyClerk's monitoring shape (its decision 0018), so one
// monitoring setup covers the desk and its edges. bad is Status.Health's list.
func Metrics(st Status, bad []string) []byte {
	var b bytes.Buffer
	healthy := 0
	if len(bad) == 0 {
		healthy = 1
	}
	ended := 0
	if st.Ended {
		ended = 1
	}
	for _, m := range []struct {
		name, kind, help string
		value            any
	}{
		{"relikey_agent_healthy", "gauge", "1 when the canary gate passes (relikey-agent status), else 0", healthy},
		{"relikey_agent_ended", "gauge", "1 when the desk ended this edge", ended},
		{"relikey_agent_status_updated_seconds", "gauge", "Unix time the status was last written", st.Updated.Unix()},
		{"relikey_agent_pulls_ok_total", "counter", "pulls that reached the desk", st.PullsOK},
		{"relikey_agent_pulls_failed_total", "counter", "pulls that failed (desk unreachable or refusing)", st.PullsFailed},
		{"relikey_agent_bundles_refused_total", "counter", "bundles and notices refused by the verifier", st.Refused},
		{"relikey_agent_bundle_serial", "gauge", "serial of the newest verified bundle", st.Serial},
		{"relikey_agent_applied_serial", "gauge", "serial whose plan was applied in full", st.AppliedSerial},
		{"relikey_agent_live_leases", "gauge", "leases live now", st.LiveLeases},
		{"relikey_agent_plan_actions", "gauge", "actions left in the current plan", st.PlanActions},
		{"relikey_agent_plan_nonempty_streak", "gauge", "consecutive ticks with a plan left over", st.NonEmptyStreak},
		{"relikey_agent_actions_executed_total", "counter", "Warpgate actions executed", st.Executed},
		{"relikey_agent_action_failures_total", "counter", "Warpgate actions that failed", st.Failures},
		{"relikey_agent_observe_errors_total", "counter", "failures to read Warpgate's state", st.ObserveErrors},
		{"relikey_agent_module_failures_total", "counter", "policy modules not fetched or not kept", st.ModuleFailures},
		{"relikey_agent_metrics_dir_failures_total", "counter", "copies to metrics_dir that failed", st.MetricsDirFailures},
		{"relikey_agent_heap_bytes", "gauge", "Go heap in use", st.HeapAlloc},
		{"relikey_agent_goroutines", "gauge", "goroutines", st.Goroutines},
	} {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", m.name, m.help, m.name, m.kind, m.name, m.value)
	}
	return b.Bytes()
}

// WriteMetricsDir writes b to dir/relikey-agent.prom for a collector that may read dir but not the state directory:
// a temporary file in dir (named so a collector skips it), made 0644 whatever the umask, then renamed over the old
// copy, so a reader sees the old file or the new one and never a partial one. Not fsynced: a copy lost in a crash is
// written again on the next tick. The error says what to change; it never names the temporary file, so a lasting
// cause reads the same on every tick.
func WriteMetricsDir(dir string, b []byte) error {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("metrics_dir %s does not exist: create it, writable by the agent's user and readable by the "+
			"collector's, or remove metrics_dir from agent.json", dir)
	case err != nil:
		return fmt.Errorf("metrics_dir %s: %w", dir, cause(err))
	case !fi.IsDir():
		return fmt.Errorf("metrics_dir %s is not a directory: set it to the directory the collector reads", dir)
	}
	f, err := os.CreateTemp(dir, ".relikey-agent-*.tmp")
	if err != nil {
		return fmt.Errorf("metrics_dir %s: cannot create a file there (%w): make it writable by the agent's user", dir,
			cause(err))
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, MetricsFile))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("metrics_dir %s: writing %s: %w (the previous copy, if any, is unchanged)", dir, MetricsFile,
			cause(err))
	}
	return nil
}

// cause strips the path from a file error: the temporary file's random name would make each tick's message new.
func cause(err error) error {
	var pe *fs.PathError
	var le *os.LinkError
	switch {
	case errors.As(err, &pe):
		return pe.Err
	case errors.As(err, &le):
		return le.Err
	}
	return err
}

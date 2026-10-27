// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"bytes"
	"fmt"
)

// Metrics is the status as Prometheus text exposition, written to metrics.prom beside
// status.json on every tick. The agent serves nothing, so it is read by a textfile
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
		{"relikey_agent_heap_bytes", "gauge", "Go heap in use", st.HeapAlloc},
		{"relikey_agent_goroutines", "gauge", "goroutines", st.Goroutines},
	} {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", m.name, m.help, m.name, m.kind, m.name, m.value)
	}
	return b.Bytes()
}

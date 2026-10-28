// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"strings"
	"testing"
)

// stableMetrics are the metric names monitoring is built on, with their types (docs/agent.md, Metrics). Dashboards and
// alert rules read them; observe_errors is the only sign of trouble reading the bastion, which exports no metrics of
// its own. Renaming or dropping one, or changing its type, is a change for a tagged release under Changed or Removed
// in the changelog: update this list only then.
var stableMetrics = map[string]string{
	"relikey_agent_healthy":                "gauge",
	"relikey_agent_status_updated_seconds": "gauge",
	"relikey_agent_live_leases":            "gauge",
	"relikey_agent_bundle_serial":          "gauge",
	"relikey_agent_applied_serial":         "gauge",
	"relikey_agent_bundles_refused_total":  "counter",
	"relikey_agent_action_failures_total":  "counter",
	"relikey_agent_observe_errors_total":   "counter",
}

func TestTheStableMetricNamesStay(t *testing.T) {
	types := map[string]string{}
	samples := map[string]bool{}
	for line := range strings.Lines(string(Metrics(Status{}, nil))) {
		f := strings.Fields(line)
		switch {
		case len(f) == 4 && f[0] == "#" && f[1] == "TYPE":
			types[f[2]] = f[3]
		case len(f) == 2:
			samples[f[0]] = true
		}
	}
	for name, kind := range stableMetrics {
		if types[name] != kind || !samples[name] {
			t.Errorf("metric %s: type %q, sample %v; want a %s with a sample (a stable name: docs/agent.md, Metrics)",
				name, types[name], samples[name], kind)
		}
	}
}

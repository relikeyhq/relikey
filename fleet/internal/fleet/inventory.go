// SPDX-License-Identifier: EUPL-1.2

package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"relikey/agent/pkg/fleetproto"
	"slices"
	"sync"
	"time"
)

// Edge is what the fleet holds about one edge.
type Edge struct {
	Edge     string             `json:"edge"`
	LastSeen time.Time          `json:"last_seen"` // the service's receive time, which it trusts for windows
	Last     *fleetproto.Report `json:"last,omitempty"`
	State    string             `json:"state"` // ok | silent | unknown (never reported)
	Basis    string             `json:"basis"` // self-reported: no clerk attests it (0026 point 1)
}

// Inventory is the fleet's view, kept in one JSON file.
type Inventory struct {
	mu      sync.Mutex
	path    string
	edges   map[string]*Edge
	silence time.Duration
}

// Open loads the inventory, or starts one for the known edges.
func Open(path string, known []string, silence time.Duration) (*Inventory, error) {
	inv := &Inventory{path: path, edges: map[string]*Edge{}, silence: silence}
	if b, err := os.ReadFile(path); err == nil {
		var stored []*Edge
		if err := json.Unmarshal(b, &stored); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, e := range stored {
			inv.edges[e.Edge] = e
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	configured := map[string]bool{}
	for _, name := range known {
		configured[name] = true
	}
	for name := range inv.edges { // an edge removed from the configuration leaves the inventory too
		if !configured[name] {
			delete(inv.edges, name)
		}
	}
	for _, name := range known {
		if inv.edges[name] == nil {
			inv.edges[name] = &Edge{Edge: name, State: "unknown", Basis: "self-reported"}
		}
	}
	return inv, nil
}

// Accept records a verified report received at now: its sequence must rise and its time must lie within fleetproto.Skew.
func (inv *Inventory) Accept(r fleetproto.Report, now time.Time) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	e := inv.edges[r.Edge]
	if e == nil {
		return fmt.Errorf("report from %q: not a known edge", r.Edge)
	}
	if e.Last != nil && r.Seq <= e.Last.Seq {
		return fmt.Errorf("report from %q: sequence %d is not above %d (a replay)", r.Edge, r.Seq, e.Last.Seq)
	}
	if r.Seq > now.Add(fleetproto.Skew).UnixMilli() {
		return fmt.Errorf("report from %q: sequence %d lies in the future", r.Edge, r.Seq)
	}
	if d := r.At.Sub(now); d > fleetproto.Skew || d < -fleetproto.Skew {
		return fmt.Errorf("report from %q: its time is %s from ours", r.Edge, d.Round(time.Second))
	}
	e.Last, e.LastSeen, e.State = &r, now, "ok"
	return inv.save()
}

// Know adds an edge to the inventory as never reported, if it is not in it yet (an edge enrolled by code).
func (inv *Inventory) Know(name string) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.edges[name] != nil {
		return nil
	}
	inv.edges[name] = &Edge{Edge: name, State: "unknown", Basis: "self-reported"}
	return inv.save()
}

// Transition is an edge whose state changed in Sweep.
type Transition struct{ Edge, From, To string }

// Sweep marks edges silent when their last report is older than the silence window, and returns what changed. An
// edge that reports again goes back to ok through Accept, which Sweep reports on its next run.
func (inv *Inventory) Sweep(now time.Time, prev map[string]string) []Transition {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var out []Transition
	for _, name := range inv.names() {
		e := inv.edges[name]
		if e.Last != nil && now.Sub(e.LastSeen) > inv.silence {
			e.State = "silent"
		}
		if p, seen := prev[name]; seen && p != e.State {
			out = append(out, Transition{name, p, e.State})
		}
		prev[name] = e.State
	}
	if len(out) > 0 {
		_ = inv.save()
	}
	return out
}

// View is the inventory, sorted by edge.
func (inv *Inventory) View() []Edge {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := []Edge{}
	for _, name := range inv.names() {
		out = append(out, *inv.edges[name])
	}
	return out
}

func (inv *Inventory) names() []string {
	names := make([]string, 0, len(inv.edges))
	for n := range inv.edges {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// save writes the inventory atomically (a crash leaves the old file or the new one, never half of one).
func (inv *Inventory) save() error {
	var list []*Edge
	for _, n := range inv.names() {
		list = append(list, inv.edges[n])
	}
	b, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	tmp := inv.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(inv.path))
}

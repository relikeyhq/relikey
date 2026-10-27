// SPDX-License-Identifier: EUPL-1.2

package apply

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"relikey/agent/internal/bastion"
	"slices"
	"strings"
	"testing"
	"time"

	"relikey/agent/internal/fakes"
	"relikey/agent/internal/httpx"
	"relikey/agent/internal/kcedge"
	"relikey/agent/internal/warpgate"
)

// sshKey is an OpenSSH public key line of the given type with a 32-byte body.
func sshKey(typ string, fill byte) string {
	blob := binary.BigEndian.AppendUint32(nil, uint32(len(typ)))
	blob = append(blob, typ...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	for range 32 {
		blob = append(blob, fill)
	}
	return typ + " " + base64.StdEncoding.EncodeToString(blob) + " vendor@laptop"
}

func visit(id, user, role string, targets []string, key string, ends time.Time) kcedge.VisitLease {
	return kcedge.VisitLease{LeaseID: id, Person: "idp:" + user, Username: user, SSHKey: key, Targets: targets,
		Role: role, Ends: ends}
}

// visitSetup has plc-operator reaching target-plc only, and wide reaching two targets.
func visitSetup(t *testing.T) (*fakes.Warpgate, bastion.Admin) {
	t.Helper()
	fw := fakes.NewWarpgate("tok", map[string][]string{"plc-operator": {"target-plc"},
		"wide": {"target-plc", "target-hmi"}})
	fw.Now = func() time.Time { return t0 }
	srv, base, pin := fw.Serve()
	t.Cleanup(srv.Close)
	hc, err := httpx.New(httpx.Options{Timeout: 10 * time.Second, PinSHA256: pin})
	if err != nil {
		t.Fatal(err)
	}
	return fw, warpgate.Bastion{C: &warpgate.Client{Base: base, Token: "tok", HTTP: hc, RetryBase: time.Millisecond}}
}

func planLive(t *testing.T, wg bastion.Admin, leases []kcedge.Lease, visits []kcedge.VisitLease) Plan {
	t.Helper()
	d := FromLive(leases, visits)
	o, err := Observe(context.Background(), wg)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ReadRoleTargets(context.Background(), wg, d); err != nil {
		t.Fatal(err)
	}
	return Compute(d, o, provider)
}

func applyLive(t *testing.T, wg bastion.Admin, leases []kcedge.Lease, visits []kcedge.VisitLease) Plan {
	t.Helper()
	p := planLive(t, wg, leases, visits)
	if r := Execute(context.Background(), wg, provider, p, 5*time.Second); len(r.Failed) > 0 {
		t.Fatalf("failed: %v", r.Failed)
	}
	return p
}

func TestAVisitInstallsKeyAndRoleUntilItsWindowThenLeavesNothing(t *testing.T) {
	fw, wg := visitSetup(t)
	key := sshKey("sk-ssh-ed25519@openssh.com", 7)
	v := []kcedge.VisitLease{visit("V-1", "vera", "plc-operator", []string{"target-plc"}, key, t0.Add(3*time.Hour))}
	applyLive(t, wg, nil, v)
	if p := planLive(t, wg, nil, v); len(p.Actions) > 0 {
		t.Fatalf("not converged: %v", p.Actions)
	}
	view, emails := fw.Snapshot(Marker)
	if !view["vera"]["plc-operator"].Equal(t0.Add(3 * time.Hour)) {
		t.Fatalf("role not set to the window's end: %v", view)
	}
	if len(emails["vera"]) != 0 {
		t.Fatalf("a visit must not add SSO sign-in: %v", emails)
	}
	want := strings.Join(strings.Fields(key)[:2], " ") // stored without the comment
	if got := fw.Keys("vera"); !slices.Equal(got, []string{want}) {
		t.Fatalf("keys %v, want %v", got, want)
	}

	sid, err := fw.OpenSession("vera", "target-plc")
	if err != nil {
		t.Fatal(err)
	}
	applyLive(t, wg, nil, nil) // the window is over: the bundle no longer carries the visit
	if fw.SessionOpen(sid) {
		t.Fatal("the visit's session stayed open after its window")
	}
	if fw.UserExists("vera", Marker) || len(fw.Keys("vera")) != 0 {
		t.Fatal("the visitor or their key stayed after the window")
	}
}

func TestAVisitRoleReachingAnUnnamedTargetIsNotAssigned(t *testing.T) {
	fw, wg := visitSetup(t)
	v := []kcedge.VisitLease{visit("V-1", "vera", "wide", []string{"target-plc"}, sshKey("ssh-ed25519", 1), t0.Add(time.Hour))}
	p := applyLive(t, wg, nil, v)
	if view, _ := fw.Snapshot(Marker); len(view["vera"]) != 0 {
		t.Fatalf("a role reaching target-hmi was assigned for a visit naming target-plc only: %v", view)
	}
	if !slices.ContainsFunc(p.Drift, func(s string) bool { return strings.Contains(s, "reaches target-hmi") }) {
		t.Fatalf("the over-reach is not reported: %v", p.Drift)
	}
}

func TestTwoVisitsForOneRoleAllowOnlyTheTargetsBothName(t *testing.T) {
	fw, wg := visitSetup(t)
	k := sshKey("ssh-ed25519", 1)
	v := []kcedge.VisitLease{
		visit("V-1", "vera", "wide", []string{"target-plc", "target-hmi"}, k, t0.Add(time.Hour)),
		visit("V-2", "vera", "wide", []string{"target-plc"}, k, t0.Add(2*time.Hour)),
	}
	applyLive(t, wg, nil, v)
	if view, _ := fw.Snapshot(Marker); len(view["vera"]) != 0 {
		t.Fatalf("the narrower visit must bound the role: %v", view)
	}
}

// A lease names one target; a role that also reaches another is not assigned: the ceiling checks only the lease's
// target, so a desk naming a wider role would reach targets no one approved (AG-11; stack attack 2026-10-25, E3).
func TestAnOrdinaryLeaseIsRefusedWhenItsRoleReachesAnotherTarget(t *testing.T) {
	fw, wg := visitSetup(t)
	l := []kcedge.Lease{lease("L-1", "vera", "wide", t0.Add(time.Hour))}
	l[0].Person, l[0].Target = "idp:vera", "target-plc"
	p := planLive(t, wg, l, nil)
	if !slices.ContainsFunc(p.Drift, func(d string) bool { return strings.Contains(d, "role wide reaches target-hmi") }) {
		t.Fatalf("no drift for the wider role: %v", p.Drift)
	}
	applyLive(t, wg, l, nil)
	if view, _ := fw.Snapshot(Marker); !view["vera"]["wide"].IsZero() {
		t.Fatalf("a role reaching an unleased target was assigned: %v", view)
	}
}

// Leases that between them name every target the role reaches let it be assigned.
func TestLeasesCoveringEveryTargetOfTheRoleAreApplied(t *testing.T) {
	fw, wg := visitSetup(t)
	l := []kcedge.Lease{lease("L-1", "vera", "wide", t0.Add(time.Hour)), lease("L-2", "vera", "wide", t0.Add(time.Hour))}
	l[0].Person, l[0].Target = "idp:vera", "target-plc"
	l[1].Person, l[1].Target = "idp:vera", "target-hmi"
	applyLive(t, wg, l, nil)
	if view, _ := fw.Snapshot(Marker); view["vera"]["wide"].IsZero() {
		t.Fatalf("the covered role is missing: %v", view)
	}
}

func TestOnlyHardwareAndEd25519KeysAreInstalled(t *testing.T) {
	for _, tc := range []struct{ name, key, why string }{
		{"rsa", sshKey("ssh-rsa", 1), "not allowed"},
		{"mismatched blob", "ssh-ed25519 " + strings.Fields(sshKey("ssh-rsa", 1))[1], "does not match"},
		{"not base64", "ssh-ed25519 !!!", "not valid base64"},
		{"no key", "ssh-ed25519", "not an OpenSSH public key line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw, wg := visitSetup(t)
			p := applyLive(t, wg, nil, []kcedge.VisitLease{
				visit("V-1", "vera", "plc-operator", []string{"target-plc"}, tc.key, t0.Add(time.Hour))})
			if fw.UserExists("vera", Marker) {
				t.Fatal("a visit with a refused key created a user")
			}
			if !slices.ContainsFunc(p.Drift, func(s string) bool { return strings.Contains(s, tc.why) }) {
				t.Fatalf("drift %v does not say %q", p.Drift, tc.why)
			}
		})
	}
}

func TestAReplacedKeyIsSwappedAndTheOldOneRemoved(t *testing.T) {
	fw, wg := visitSetup(t)
	old, neu := sshKey("ssh-ed25519", 1), sshKey("ssh-ed25519", 2)
	applyLive(t, wg, nil, []kcedge.VisitLease{visit("V-1", "vera", "plc-operator", []string{"target-plc"}, old, t0.Add(time.Hour))})
	applyLive(t, wg, nil, []kcedge.VisitLease{visit("V-2", "vera", "plc-operator", []string{"target-plc"}, neu, t0.Add(time.Hour))})
	if got := fw.Keys("vera"); len(got) != 1 || !strings.HasPrefix(neu, got[0]) {
		t.Fatalf("keys %v, want only the new one", got)
	}
}

func TestAVisitUnderAnotherPersonsUsernameIsRefused(t *testing.T) {
	fw, wg := visitSetup(t)
	l := []kcedge.Lease{lease("L-1", "ann", "plc-operator", t0.Add(time.Hour))}
	l[0].Person = "idp:ann"
	v := []kcedge.VisitLease{visit("V-1", "ann", "plc-operator", []string{"target-plc"}, sshKey("ssh-ed25519", 1), t0.Add(time.Hour))}
	v[0].Person = "idp:mallory"
	p := applyLive(t, wg, l, v)
	if fw.UserExists("ann", Marker) {
		t.Fatal("a username shared by two people was applied")
	}
	if !slices.ContainsFunc(p.Drift, func(s string) bool { return strings.Contains(s, "share the username ann") }) {
		t.Fatalf("drift %v", p.Drift)
	}
}

// A lease that names no target is refused: there is nothing to hold its role's reach against (AG-11, fail closed).
func TestALeaseWithoutATargetIsRefused(t *testing.T) {
	l := lease("L-1", "vera", "plc-operator", t0.Add(time.Hour))
	l.Target = ""
	d := FromLeases([]kcedge.Lease{l})
	if d.Users["vera"] != nil || !slices.ContainsFunc(d.Drift, func(s string) bool { return strings.Contains(s, "names no username, role or target") }) {
		t.Fatalf("a lease without a target was taken: users %v, drift %v", d.Users, d.Drift)
	}
}

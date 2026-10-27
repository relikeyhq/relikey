// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"maps"
	"slices"
	"strings"

	"relikey/agent/internal/apply"
	"relikey/agent/pkg/events"
)

// OCSF classes the agent's events use (decision 0025 point 1), checked against OCSF 1.6.0 (ocsfVersion).
const (
	ocsfVersion           = "1.6.0"
	ocsfAccountChange     = 3001 // Identity & Access Management: an account created or deleted, its sign-ins bound
	ocsfAuthentication    = 3002 // a session the agent closed: a logoff
	ocsfUserAccess        = 3005 // User Access Management: a role granted, revoked or extended
	ocsfComplianceFinding = 2003 // Findings: an unmanaged account holding a governed role (a required outcome failing)
	ocsfDetectionFinding  = 2004 // Findings: a refused bundle, an ended edge
)

// actionEvents are the event type, OCSF class and activity of each action the agent carries out. Account Change
// activities: 1 Create, 6 Delete, 99 Other; User Access Management: 1 Assign Privileges, 2 Revoke Privileges, 99 Other;
// Authentication: 2 Logoff.
var actionEvents = map[apply.Kind]struct {
	typ      string
	class    int
	activity int
}{
	apply.CreateUser:   {"relikey.account.created.v1", ocsfAccountChange, 1},
	apply.DeleteUser:   {"relikey.account.deleted.v1", ocsfAccountChange, 6},
	apply.AddRole:      {"relikey.account.role_granted.v1", ocsfUserAccess, 1},
	apply.RemoveRole:   {"relikey.account.role_revoked.v1", ocsfUserAccess, 2},
	apply.SetExpiry:    {"relikey.account.role_extended.v1", ocsfUserAccess, 99},
	apply.AddSSO:       {"relikey.account.sso_bound.v1", ocsfAccountChange, 99},
	apply.DeleteSSO:    {"relikey.account.sso_unbound.v1", ocsfAccountChange, 99},
	apply.AddKey:       {"relikey.account.key_added.v1", ocsfAccountChange, 99},
	apply.DeleteKey:    {"relikey.account.key_removed.v1", ocsfAccountChange, 99},
	apply.CloseSession: {"relikey.session.closed.v1", ocsfAuthentication, 2},
}

func (a *Agent) account(name string) string { return "account:" + a.Pins.Edge + "/" + name }

// emit builds and writes one event; a malformed one is a bug, logged, never written.
func (a *Agent) emit(typ, subject, outcome, severity, reason string, ocsf map[string]any) {
	if a.Emit == nil {
		return
	}
	ev, err := events.New(a.Pins.Edge, typ, subject, outcome, severity, reason, a.Clock.Now(), ocsf)
	if err != nil {
		a.Log.Error("event not emitted", "err", err)
		return
	}
	a.Emit(ev)
}

func ocsfClass(class int) (string, int) {
	switch class {
	case ocsfAccountChange:
		return "Account Change", 3
	case ocsfAuthentication:
		return "Authentication", 3
	case ocsfUserAccess:
		return "User Access Management", 3
	case ocsfComplianceFinding:
		return "Compliance Finding", 2
	default:
		return "Detection Finding", 2
	}
}

// metadata is OCSF's required metadata: the version and the product.
func metadata() map[string]any {
	return map[string]any{"version": ocsfVersion, "product": map[string]any{"name": "ReliKey edge agent", "vendor_name": "ReliKey"}}
}

// emitApplied writes one event per action the bastion took.
func (a *Agent) emitApplied(done []apply.Action) {
	for _, x := range done {
		m, ok := actionEvents[x.Kind]
		if !ok {
			continue
		}
		name, category := ocsfClass(m.class)
		detail := map[string]any{"action": x.Kind.String(), "why": x.Why}
		if x.Role != "" {
			detail["role"] = x.Role
		}
		ocsf := map[string]any{"class_uid": m.class, "category_uid": category, "class_name": name,
			"activity_id": m.activity, "status": "Success", "status_detail": x.Why,
			"user": map[string]any{"name": x.Username, "uid": x.UserID}, "metadata": metadata(),
			"unmapped": map[string]any{"relikey": detail}}
		if x.Role != "" && m.class == ocsfUserAccess {
			ocsf["privileges"] = []string{x.Role}
		}
		if x.Session != "" {
			ocsf["session"] = map[string]any{"uid": x.Session}
		}
		a.emit(m.typ, a.account(x.Username), events.Success, events.Info, "applied", ocsf)
	}
}

// finding is a Compliance or Detection Finding: activity 1 Create (found), 3 Close (gone).
func finding(class int, title, uid string, found bool, severityID int, detail map[string]any) map[string]any {
	activity, status := 1, "New"
	if !found {
		activity, status = 3, "Resolved"
	}
	name, category := ocsfClass(class)
	return map[string]any{"class_uid": class, "category_uid": category, "class_name": name,
		"activity_id": activity, "status": status, "severity_id": severityID, "metadata": metadata(),
		"finding_info": map[string]any{"uid": uid, "title": title},
		"unmapped":     map[string]any{"relikey": detail}}
}

// emitRogue reports a change in the unmanaged accounts holding governed roles: found once, then gone once, never on
// every tick (finding 8). The state is the agent's memory of what it reported; after a restart it reports the
// current set again, which a reader takes as a repeat, not news.
func (a *Agent) emitRogue(o *apply.Observed) {
	if o.Rogue == nil {
		return // no check ran this tick: the last reported state stands
	}
	current := map[string]string{}
	for name, roles := range o.Rogue {
		if len(roles) > 0 {
			current[name] = strings.Join(roles, ",")
		}
	}
	for name, roles := range a.rogue { // unchecked accounts, and everything when the check was partial, keep their state
		if _, seen := current[name]; !seen && (o.RoguePartial || o.RogueUnchecked[name]) {
			current[name] = roles
		}
	}
	for _, name := range slices.Sorted(maps.Keys(current)) {
		if a.rogue[name] == current[name] {
			continue
		}
		a.emit("relikey.drift.rogue_account.v1", a.account(name), events.Failure, events.Warning, "drift",
			finding(ocsfComplianceFinding, "an account the agent does not manage holds a governed role", "rogue:"+name, true, 3, nil)) // which roles stays in the local drift report (decision 0025 point 7)
	}
	for _, name := range slices.Sorted(maps.Keys(a.rogue)) {
		if _, still := current[name]; !still {
			a.emit("relikey.drift.rogue_account.v1", a.account(name), events.Success, events.Info, "resolved",
				finding(ocsfComplianceFinding, "an account the agent does not manage holds a governed role", "rogue:"+name, false, 1, nil))
		}
	}
	a.rogue = current
}

// emitRefused reports a refused bundle by a reason code; the full reason stays in the local log and status (decision
// 0025 point 7). The edge keeps what it holds.
func (a *Agent) emitRefused(why string) {
	a.emit("relikey.bundle.refused.v1", "edge:"+a.Pins.Edge+"/bundle", events.Failure, events.Critical, "refused",
		finding(ocsfDetectionFinding, "a bundle from the desk was refused", "bundle-refused", true, 4,
			map[string]any{"code": refusalCode(why)}))
}

// refusalCode maps a refusal to a coarse code a monitor can count on.
func refusalCode(why string) string {
	for _, c := range []struct{ code, needle string }{
		{"replay", "not above the floor"}, {"signature", "signer"}, {"signature", "signature"},
		{"clock", "clock"}, {"clock", "issued"}, {"ceiling", "ceiling"}, {"other_edge", "another edge"},
		{"malformed", "malformed"}, {"governed_roles", "governed_roles"}, {"ended_notice", "ended notice"},
	} {
		if strings.Contains(why, c.needle) {
			return c.code
		}
	}
	return "other"
}

// emitEnded reports that the desk ended this edge.
func (a *Agent) emitEnded(reason string) {
	a.emit("relikey.edge.ended.v1", "edge:"+a.Pins.Edge+"/enrolment", events.Success, events.Critical, "ended",
		finding(ocsfDetectionFinding, "the desk ended this edge: all access removed", "edge-ended", true, 5, map[string]any{"reason": reason}))
}

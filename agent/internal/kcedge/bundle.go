// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	BundleFormat  = "kc-edge-bundle-v3"  // 0.23.0: the ceiling sealed as the officer signed it, modules by hash
	CeilingFormat = "kc-edge-ceiling-v2" // sealed by the officer (amendment 0014d)
	ReleaseFormat = "kc-policy-release-v1"
	// Skew is how far an edge's clock may differ from the desk's (edge.py SKEW).
	Skew = 300 * time.Second
)

var (
	classes     = []string{"low", "elevated", "privileged"}
	ceilingKeys = []string{"classes", "edge", "format", "key_id", "max_lease_hours", "max_offline_hours", "persons",
		"ports", "profile", "remote_reach", "roles", "serial", "signed_at", "targets"}
	hex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	isoTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)
)

// Pins are pinned on site, never taken from the desk.
type Pins struct {
	Edge       string  `json:"edge"`
	BundleKey  string  `json:"bundle_key"`
	OfficerKey string  `json:"officer_key"`
	ReleaseKey *string `json:"release_key"`
}

// State is what the edge keeps between pulls; the caller stores the returned
// state only when the bundle verified.
type State struct {
	Serial        int64  `json:"serial"`
	Newest        string `json:"newest,omitempty"`
	CeilingSerial int64  `json:"ceiling_serial"`
}

// Lease is a lease as the bundle carries it (build_bundle).
type Lease struct {
	LeaseID         string   `json:"lease_id"`
	Person          string   `json:"person"`
	Username        string   `json:"username"`
	KeyID           string   `json:"key_id"`
	Target          string   `json:"target"`
	Role            string   `json:"role"`
	Roles           []string `json:"roles"`
	Class           string   `json:"class"`
	From            string   `json:"from"`
	Until           string   `json:"until"`
	MaxSessionHours int64    `json:"max_session_hours"`
	// Email binds the Warpgate SSO credential (decision 0010); KeyClerk v0.19.0 does
	// not send it yet, and the agent reports the gap.
	Email string `json:"email"`
	// Ends is when the lease stops being live on its own: until, or the end of its
	// offline horizon, whichever is first. Set by the verifier, never on the wire.
	Ends time.Time `json:"-"`
}

// VisitLease is a visit lease as the bundle carries it.
type VisitLease struct {
	LeaseID  string   `json:"lease_id"`
	Person   string   `json:"person"`
	Username string   `json:"username"`
	SSHKey   string   `json:"ssh_key"`
	Targets  []string `json:"targets"`
	Role     string   `json:"role"`
	From     string   `json:"from"`
	Until    string   `json:"until"`
	// Ends is the signed window's end (a visit lease ends at its own window, decision
	// 0007). Set by the verifier, never on the wire.
	Ends time.Time `json:"-"`
}

// policy names its modules by hash only; the agent fetches a module it does not hold
// by GET /api/v1/edge/module/{sha256} and checks it with VerifyModule (0.23.0).
type policy struct {
	Modules map[string]Object `json:"modules"`
	Release *Sealed           `json:"release"`
}

// ModuleRefs are the policy modules a bundle names: name to sha256.
func ModuleRefs(s Sealed, pins Pins) (map[string]string, error) {
	o, err := open(s, pins)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if o.b.Policy != nil {
		for name, m := range o.b.Policy.Modules {
			if sum, ok := m["sha256"].(string); ok {
				out[name] = sum
			}
		}
	}
	return out, nil
}

// VerifyModule is keyclerk.edge.verify_module: a fetched module is exactly the bytes
// its bundle (and release manifest) named, and WebAssembly.
func VerifyModule(raw []byte, expectedSHA256 string) []string {
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expectedSHA256 {
		return []string{"the module's bytes are not the sha256 its bundle names"}
	}
	if !bytes.HasPrefix(raw, []byte("\x00asm")) {
		return []string{"the module is not WebAssembly"}
	}
	return nil
}

// bundle holds the typed fields; pointers mark members the reference indexes
// directly (a missing one crashes edge.py, so it is a refusal here).
type bundle struct {
	Edge        string            `json:"edge"`
	Serial      *int64            `json:"serial"`
	Issued      *string           `json:"issued"`
	Horizons    *map[string]int64 `json:"horizons"`
	Leases      *[]Lease          `json:"leases"`
	VisitLeases *[]VisitLease     `json:"visit_leases"`
	Revoked     *[]string         `json:"revoked"`
	Policy      *policy           `json:"policy"`
}

// CeilingEntry is what the ceiling policy module is asked about one lease.
type CeilingEntry struct {
	Kind    string   `json:"kind"`
	Person  string   `json:"person"`
	Roles   []string `json:"roles"`
	Targets []string `json:"targets"`
	Class   string   `json:"class"`
	Hours   int64    `json:"hours"`
	// AttestedProfile is the edge's attested profile (visit leases only).
	AttestedProfile string `json:"attested_profile,omitempty"`
}

// AttestedProfile is the profile this agent attests: basic until hardware attestation
// lands (R-10). The ceiling refuses visit leases on a basic edge.
const AttestedProfile = "basic"

// CeilingPolicy runs the verified ceiling module; nil leaves it out, as the
// conformance verifier cases do.
type CeilingPolicy func(ceiling Object, entry CeilingEntry) (allow bool, err error)

// Applied is what holds now.
type Applied struct {
	Leases           []Lease      `json:"leases"`
	VisitLeases      []VisitLease `json:"visit_leases"`
	Revoked          []string     `json:"revoked"`
	RefusedByCeiling []string     `json:"refused_by_ceiling"`
	// GovernedRoles are the edge roles the clerk governs here (KeyClerk decision 0025): nil when the bundle carries no
	// catalogue, which is never "none governed"; an empty list, signed, is. The agent reports an unmanaged account
	// holding one, never changing it (full-stack run 2, finding 8).
	GovernedRoles *[]string `json:"governed_roles"`
	State         State     `json:"state"`
}

// Refusal lists every reason a bundle was refused.
type Refusal struct{ Reasons []string }

func (r *Refusal) Error() string { return "bundle refused: " + errorList(r.Reasons) }

func refuse(reasons ...string) *Refusal { return &Refusal{Reasons: reasons} }

// ParseTime reads a signed time; only the exact form KeyClerk writes is accepted.
func ParseTime(s string) (time.Time, error) {
	if !isoTime.MatchString(s) {
		return time.Time{}, fmt.Errorf("time %q: a UTC time like 2026-10-23T10:00:00Z", s)
	}
	return time.Parse("2006-01-02T15:04:05Z", s)
}

func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// opened is a bundle whose signature, bytes and required members have been checked.
type opened struct {
	b        bundle
	obj      Object
	issued   time.Time
	governed *[]string
}

// governedRoles checks the optional governed_roles member (KeyClerk decision 0025): a list of SCIM Group shapes,
// {displayName, externalId?}, both strings, displayName not empty, each role once, nothing else. A malformed one,
// null included, refuses the whole bundle; absent returns nil.
func governedRoles(obj Object) (*[]string, string) {
	v, present := obj["governed_roles"]
	if !present {
		return nil, ""
	}
	const shape = "governed_roles: a list of {displayName, externalId?}, both strings"
	arr, ok := v.([]Value)
	if !ok {
		return nil, shape
	}
	names, seen := []string{}, map[string]bool{}
	for _, x := range arr {
		m, ok := x.(Object)
		if !ok {
			return nil, shape
		}
		name, ok := m["displayName"].(string)
		if !ok || name == "" {
			return nil, shape
		}
		for k, val := range m {
			if _, isStr := val.(string); (k != "displayName" && k != "externalId") || !isStr {
				return nil, shape
			}
		}
		names = append(names, name)
		if seen[name] {
			return nil, "governed_roles: each role once"
		}
		seen[name] = true
	}
	return &names, ""
}

func open(s Sealed, pins Pins) (*opened, error) {
	obj, raw, err := Unseal(s, pins.BundleKey, BundleFormat)
	if err != nil {
		return nil, refuse(err.Error())
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, refuse("a malformed bundle: " + err.Error())
	}
	if b.Serial == nil || b.Issued == nil || b.Horizons == nil || b.Leases == nil || b.VisitLeases == nil || b.Revoked == nil {
		return nil, refuse("a malformed bundle: serial, issued, horizons, leases, visit_leases and revoked are required")
	}
	issued, err := ParseTime(*b.Issued)
	if err != nil {
		return nil, refuse("issued: " + err.Error())
	}
	governed, why := governedRoles(obj)
	if why != "" {
		return nil, refuse(why)
	}
	return &opened{b: b, obj: obj, issued: issued, governed: governed}, nil
}

// ceiling checks the officer's sealed ceiling against the floor and returns what it says.
func (o *opened) ceiling(pins Pins, floor int64) (Object, []string) {
	c := o.obj["ceiling"]
	if c == nil {
		var errs []string
		if len(*o.b.Leases) > 0 || len(*o.b.VisitLeases) > 0 {
			errs = append(errs, "leases without a ceiling: refused (fail closed)")
		}
		if floor != 0 {
			errs = append(errs, "a bundle without the ceiling the edge already holds")
		}
		return nil, errs
	}
	if _, ok := c.(Object); !ok {
		return nil, []string{"ceiling: the officer's sealed ceiling or null"}
	}
	errs, doc := CheckCeiling(pins.Edge, pins.OfficerKey, c, floor)
	return doc, errs
}

// VerifyBundle is keyclerk.edge.verify_bundle in Go: the same checks in the same
// order, the same verdict and the same live leases.
func VerifyBundle(s Sealed, pins Pins, state State, now time.Time, ceilingPolicy CeilingPolicy) (*Applied, error) {
	o, err := open(s, pins)
	if err != nil {
		return nil, err
	}
	var errs []string
	if o.b.Edge != pins.Edge {
		errs = append(errs, "a bundle for another edge")
	}
	if *o.b.Serial <= state.Serial {
		errs = append(errs, fmt.Sprintf("serial %d is not above the floor %d: an old bundle replayed", *o.b.Serial, state.Serial))
	}
	if o.issued.After(now.Add(Skew)) {
		errs = append(errs, "issued in the future: refused (a clock pushed forward must not stretch leases)")
	}
	var newest time.Time
	if state.Newest != "" {
		if newest, err = ParseTime(state.Newest); err != nil {
			return nil, refuse("the stored newest signed time: " + err.Error())
		}
		if now.Before(newest.Add(-Skew)) {
			errs = append(errs, "the clock is before the newest signed time seen: refused (time never goes back)")
		}
		if o.issued.Before(newest.Add(-Skew)) {
			errs = append(errs, "issued before the newest signed time seen")
		}
	}
	errs = append(errs, checkPolicy(o.b.Policy, pins)...)
	doc, cerrs := o.ceiling(pins, state.CeilingSerial)
	errs = append(errs, cerrs...)
	if len(errs) > 0 {
		return nil, refuse(errs...)
	}
	out, err := o.evaluate(doc, now, ceilingPolicy)
	if err != nil {
		return nil, err
	}
	ceilingSerial := state.CeilingSerial
	if doc != nil {
		ceilingSerial, _ = asInt(doc["serial"])
	}
	if newest.IsZero() || o.issued.After(newest) {
		newest = o.issued // signed times only
	}
	out.State = State{Serial: *o.b.Serial, Newest: formatTime(newest), CeilingSerial: ceilingSerial}
	return out, nil
}

// LiveAt re-evaluates a bundle the edge already accepted (VerifyBundle) at another
// moment: the signature, the edge and the ceiling's signature are checked again, the
// floors are not (the bundle set them). The agent calls it on every tick, so leases
// end on the edge at their end without asking KeyClerk (decision 0008, GE-6).
func LiveAt(s Sealed, pins Pins, now time.Time, ceilingPolicy CeilingPolicy) (*Applied, error) {
	o, err := open(s, pins)
	if err != nil {
		return nil, err
	}
	if o.b.Edge != pins.Edge {
		return nil, refuse("a bundle for another edge")
	}
	doc, errs := o.ceiling(pins, 0)
	if len(errs) > 0 {
		return nil, refuse(errs...)
	}
	out, err := o.evaluate(doc, now, ceilingPolicy)
	if err != nil {
		return nil, err
	}
	out.State = State{Serial: *o.b.Serial, Newest: formatTime(o.issued)}
	return out, nil
}

// ContentDigest is keyclerk.edge.bundle_digest: sha256 of the signed bundle body without serial, issued, format and
// key_id, so two bundles with the same leases, revocations, ceiling, policy and governed roles have the same digest
// (KeyClerk decision 0026: what a long-poll waits for). The signature is checked against the pinned key first.
func ContentDigest(s Sealed, pins Pins) (string, error) {
	obj, _, err := Unseal(s, pins.BundleKey, BundleFormat)
	if err != nil {
		return "", err
	}
	body := Object{}
	for k, v := range obj {
		if k != "serial" && k != "issued" && k != "format" && k != "key_id" {
			body[k] = v
		}
	}
	sum := sha256.Sum256(Encode(body))
	return hex.EncodeToString(sum[:]), nil
}

// Issued is the bundle's signed issue time and serial.
func Issued(s Sealed, pins Pins) (time.Time, int64, error) {
	o, err := open(s, pins)
	if err != nil {
		return time.Time{}, 0, err
	}
	return o.issued, *o.b.Serial, nil
}

func (o *opened) evaluate(doc Object, now time.Time, ceilingPolicy CeilingPolicy) (*Applied, error) {
	b := o.b
	offlineCap := int64(0)
	if doc != nil {
		offlineCap, _ = asInt(doc["max_offline_hours"])
	}
	age := now.Sub(o.issued)
	out := &Applied{Leases: []Lease{}, VisitLeases: []VisitLease{}, Revoked: *b.Revoked, RefusedByCeiling: []string{},
		GovernedRoles: o.governed}
	for _, x := range *b.Leases {
		from, err1 := ParseTime(x.From)
		until, err2 := ParseTime(x.Until)
		if err1 != nil || err2 != nil {
			return nil, refuse(fmt.Sprintf("lease %s: from and until must be UTC times", x.LeaseID))
		}
		if ceilingPolicy != nil {
			// Python: max(1, int(seconds // 3600)); // floors, Go's / truncates.
			hours := max(1, floorDiv(int64(until.Sub(from)/time.Second), 3600))
			roles := x.Roles
			if roles == nil {
				roles = []string{}
			}
			allow, err := ceilingPolicy(doc, CeilingEntry{Kind: "lease", Person: x.Person, Roles: roles,
				Targets: []string{x.Target}, Class: x.Class, Hours: hours})
			if err != nil {
				return nil, refuse("the ceiling policy failed: " + err.Error())
			}
			if !allow {
				out.RefusedByCeiling = append(out.RefusedByCeiling, x.LeaseID)
				continue
			}
		}
		classHorizon, ok := (*b.Horizons)[x.Class]
		if !ok {
			continue // a class without a horizon is never live (KC-6)
		}
		horizon := min(classHorizon, offlineCap) // the ceiling narrows offline validity
		if !from.After(now) && now.Before(until) && age <= time.Duration(horizon)*time.Hour &&
			!slices.Contains(*b.Revoked, x.LeaseID) {
			x.Ends = until
			if h := o.issued.Add(time.Duration(horizon) * time.Hour); h.Before(until) {
				x.Ends = h
			}
			out.Leases = append(out.Leases, x)
		}
	}
	for _, x := range *b.VisitLeases {
		from, err1 := ParseTime(x.From)
		until, err2 := ParseTime(x.Until)
		if err1 != nil || err2 != nil {
			return nil, refuse(fmt.Sprintf("visit lease %s: from and until must be UTC times", x.LeaseID))
		}
		if ceilingPolicy != nil {
			// KeyClerk's reference verifier does not run the ceiling on visit leases, though
			// ceiling.rego has visit rules (an assured edge, a window within the offline
			// cap). The agent runs them: the officer's ceiling bounds a taken-over desk.
			hours := max(1, floorDiv(int64(until.Sub(from)/time.Second), 3600))
			targets := x.Targets
			if targets == nil {
				targets = []string{}
			}
			allow, err := ceilingPolicy(doc, CeilingEntry{Kind: "visit", Person: x.Person, Roles: []string{},
				Targets: targets, Hours: hours, AttestedProfile: AttestedProfile})
			if err != nil {
				return nil, refuse("the ceiling policy failed: " + err.Error())
			}
			if !allow {
				out.RefusedByCeiling = append(out.RefusedByCeiling, x.LeaseID)
				continue
			}
		}
		if !from.After(now) && now.Before(until) && !slices.Contains(*b.Revoked, x.LeaseID) {
			x.Ends = until
			out.VisitLeases = append(out.VisitLeases, x)
		}
	}
	return out, nil
}

// checkPolicy: every module is named by {sha256} only, 64 lower-case hex (its bytes
// come from GET /api/v1/edge/module and are checked when fetched, KC-9), and, with a
// release key pinned, is the one the signed release manifest names.
func checkPolicy(p *policy, pins Pins) []string {
	var errs []string
	var mods map[string]Object
	if p != nil {
		mods = p.Modules
	}
	names := make([]string, 0, len(mods))
	for name := range mods {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		sum, ok := mods[name]["sha256"].(string)
		if len(mods[name]) != 1 || !ok || !hex64.MatchString(sum) {
			errs = append(errs, fmt.Sprintf("policy module %s: {sha256} only, 64 lower-case hex (its bytes come from GET /edge/module)", name))
		}
	}
	if len(errs) > 0 || pins.ReleaseKey == nil || *pins.ReleaseKey == "" {
		return errs
	}
	if p == nil || p.Release == nil {
		return append(errs, "the policy release does not verify: no release manifest")
	}
	manifest, _, err := Unseal(*p.Release, *pins.ReleaseKey, ReleaseFormat)
	if err != nil {
		return append(errs, "the policy release does not verify: "+err.Error())
	}
	released, _ := manifest["modules"].(Object)
	for _, name := range names {
		if released[name] != mods[name]["sha256"] {
			errs = append(errs, fmt.Sprintf("policy module %s is not the released one", name))
		}
	}
	return errs
}

// CheckCeiling is keyclerk.edge.check_ceiling: the errors in a sealed ceiling, empty
// when it may be used, and what it says. The officer's signature is over its exact
// bytes (amendment 0014d); nothing is re-serialised to check it.
func CheckCeiling(edgeID, officerHex string, sealed Value, floor int64) ([]string, Object) {
	c, _, err := UnsealValue(sealed, officerHex, CeilingFormat)
	if err != nil {
		if strings.HasPrefix(err.Error(), "a wrong signer") {
			return []string{"the ceiling is not signed with the edge officer's key"}, nil
		}
		return []string{"the ceiling: " + err.Error()}, nil
	}
	if !sameKeys(c, ceilingKeys) {
		return []string{"a ceiling has exactly " + strings.Join(ceilingKeys, ", ")}, nil
	}
	var errs []string
	if c["edge"] != edgeID {
		errs = append(errs, "the ceiling names another edge")
	}
	if serial, ok := asInt(c["serial"]); !ok || serial < 1 {
		errs = append(errs, "serial: a whole number from 1")
	} else if serial < floor {
		errs = append(errs, fmt.Sprintf("a ceiling older than the one held (serial %d below %d)", serial, floor))
	}
	for _, k := range []string{"persons", "roles", "targets", "classes"} {
		if !strs(c[k]) {
			errs = append(errs, k+": a list of names")
		}
	}
	if strs(c["classes"]) {
		for _, v := range c["classes"].([]Value) {
			if !slices.Contains(classes, v.(string)) {
				errs = append(errs, "classes are low, elevated, privileged")
				break
			}
		}
	}
	for _, lim := range []struct {
		key string
		top int64
	}{{"max_lease_hours", 24 * 366}, {"max_offline_hours", 24 * 30}} {
		if v, ok := asInt(c[lim.key]); !ok || v < 0 || v > lim.top {
			errs = append(errs, fmt.Sprintf("%s: 0 to %d hours", lim.key, lim.top))
		}
	}
	if p := c["profile"]; p != "assured" && p != "basic" {
		errs = append(errs, "profile: assured or basic")
	}
	if r := c["remote_reach"]; r != "off" && r != "tunnel" && r != "netbird" {
		errs = append(errs, "remote_reach: off, tunnel or netbird")
	}
	ports, ok := c["ports"].([]Value)
	for _, p := range ports {
		if n, isInt := asInt(p); !isInt || n < 1 || n > 65535 {
			ok = false
		}
	}
	if !ok {
		errs = append(errs, "ports: whole numbers from 1 to 65535")
	}
	if s, isStr := c["signed_at"].(string); !isStr || !isoTime.MatchString(s) {
		errs = append(errs, "signed_at: a UTC time like 2026-10-23T10:00:00Z")
	}
	if len(errs) > 0 {
		return errs, nil
	}
	return nil, c
}

func sameKeys(o Object, keys []string) bool {
	if len(o) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}

// asInt reads a whole number; booleans are not numbers (edge.py excludes bool).
func asInt(v Value) (int64, bool) {
	n, ok := v.(Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

// strs is edge.py _strs: a list of at most 500 strings of 1 to 256 characters
// (Python counts code points).
func strs(v Value) bool {
	l, ok := v.([]Value)
	if !ok || len(l) > 500 {
		return false
	}
	for _, e := range l {
		s, ok := e.(string)
		if !ok || s == "" || utf8.RuneCountInString(s) > 256 {
			return false
		}
	}
	return true
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

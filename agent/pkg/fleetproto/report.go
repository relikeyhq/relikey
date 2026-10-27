// SPDX-License-Identifier: EUPL-1.2

// Package fleetproto is the fleet report's format (decision 0026), shared by the edge agent and the fleet service
// (relikey/fleet): the report, its signature and the edge's client. The service keeps the inventory and raises the
// silence alarm. It works with any clerk or none, so without a clerk the
// view is self-reported, not attested (0026 point 1). It carries evidence and governance facts, never device
// telemetry (0021), and drift as reason codes only (0025 point 7): the detail stays on the edge.
package fleetproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// ReportContext domain-separates a fleet report's signature from every other use of the edge's enrolment key (the
// clerk's signed requests are kc-edge-request-v2): a report can never pass for a clerk request, nor the reverse.
const ReportContext = "relikey-fleet-report-v1"

// Skew is how far a report's time may lie from the service's clock.
const Skew = 5 * time.Minute

// Report is what an edge says about itself.
type Report struct {
	Edge          string    `json:"edge"`
	Seq           int64     `json:"seq"` // rises with every report from this edge: a replay is refused
	At            time.Time `json:"at"`  // the edge's trusted time when it reported
	Release       string    `json:"release"`
	Mode          string    `json:"mode"`
	Profile       string    `json:"profile"`
	Serial        int64     `json:"serial"`
	AppliedSerial int64     `json:"applied_serial"`
	LiveLeases    int       `json:"live_leases"`
	DriftCodes    []string  `json:"drift_codes"` // codes, never the drift text (0025 point 7)
	ClerkTLS      string    `json:"clerk_tls_group,omitempty"`
	BastionTLS    string    `json:"bastion_tls_group,omitempty"`
}

// Signed is a report on the wire: the exact JSON bytes and the edge's signature over context and bytes.
type Signed struct {
	Report    string `json:"report"`    // base64 of the exact report bytes
	Signature string `json:"signature"` // hex Ed25519 over ReportContext + "\n" + bytes
}

func message(raw []byte) []byte { return append([]byte(ReportContext+"\n"), raw...) }

// Sign seals a report with the edge's enrolment key.
func Sign(key ed25519.PrivateKey, r Report) (Signed, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Report: base64.StdEncoding.EncodeToString(raw),
		Signature: hex.EncodeToString(ed25519.Sign(key, message(raw)))}, nil
}

// Verify checks a signed report against the known edges' keys and returns the report. It does not check the
// sequence or the time; the inventory does, against what it holds.
func Verify(s Signed, keys map[string]ed25519.PublicKey) (Report, error) {
	raw, err := base64.StdEncoding.DecodeString(s.Report)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s.Report {
		return Report{}, errors.New("report: not canonical base64")
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Report{}, errors.New("report: the signature is 128 hex characters")
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return Report{}, fmt.Errorf("report: %w", err)
	}
	key, known := keys[r.Edge]
	if !known {
		return Report{}, fmt.Errorf("report from %q: not a known edge", r.Edge)
	}
	if !ed25519.Verify(key, message(raw), sig) {
		return Report{}, fmt.Errorf("report from %q: the signature does not verify against its key", r.Edge)
	}
	if err := r.Check(); err != nil {
		return Report{}, fmt.Errorf("report from %q: %w", r.Edge, err)
	}
	return r, nil
}

var (
	releaseRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}$`)
	wordRE    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	groupRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{0,32}$`)
)

// MaxDriftCodes is the most codes one report carries.
const MaxDriftCodes = 16

// Check holds every field to a strict form: plain ASCII words of bounded length, so what an edge says about itself
// can be shown as it is, never as text that rearranges or hides the page around it (GUI red team, 2026-10-25).
func (r Report) Check() error {
	switch {
	case !releaseRE.MatchString(r.Release):
		return errors.New("release: letters, digits and . + _ -, at most 40")
	case r.Mode != "enforce" && r.Mode != "shadow":
		return errors.New("mode: enforce or shadow")
	case !wordRE.MatchString(r.Profile):
		return errors.New("profile: a lower-case word")
	case !groupRE.MatchString(r.ClerkTLS) || !groupRE.MatchString(r.BastionTLS):
		return errors.New("TLS group: letters, digits, _ and -")
	case len(r.DriftCodes) > MaxDriftCodes:
		return fmt.Errorf("drift codes: at most %d", MaxDriftCodes)
	case r.Serial < 0 || r.AppliedSerial < 0 || r.LiveLeases < 0 || r.LiveLeases > 100000:
		return errors.New("counts: not negative, and a believable number of leases")
	}
	for _, c := range r.DriftCodes {
		if !wordRE.MatchString(c) {
			return errors.New("drift codes: lower-case words")
		}
	}
	return nil
}

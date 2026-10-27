// SPDX-License-Identifier: EUPL-1.2

// Package events is what the edge agent emits for monitoring (decision 0025 point 1): one JSON line per event, a
// CloudEvents 1.0 envelope whose data is one OCSF event, in KeyClerk's shape (type relikey.<noun>.<verb>.v<n>, the
// subject an entity id). The platform's alert-event fields (ts, solution, event, outcome, severity, reason, entity)
// ride along as CloudEvents extension attributes, so the same line satisfies both readers. Subjects are bastion
// accounts and lease ids, never a person's name or e-mail: only the clerk's records join them to a person.
package events

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

// Type is relikey.<noun>.<verb>.v<n>, lower case with underscores: KeyClerk's pattern and the platform's event-name
// pattern at once.
var Type = regexp.MustCompile(`^relikey\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.v[0-9]+$`)

// Outcomes and severities of the platform's alert-event contract.
const (
	Success = "success"
	Failure = "failure"
	Unknown = "unknown"

	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// Event is one line.
type Event struct {
	SpecVersion     string `json:"specversion"`
	ID              string `json:"id"`
	Source          string `json:"source"`
	Type            string `json:"type"`
	Subject         string `json:"subject"`
	Time            string `json:"time"`
	DataContentType string `json:"datacontenttype"`
	// The platform's alert-event fields, as CloudEvents extension attributes.
	TS       string `json:"ts"`
	Solution string `json:"solution"`
	Name     string `json:"event"`
	Outcome  string `json:"outcome"`
	Severity string `json:"severity,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Entity   string `json:"entity"`
	// Data is the OCSF event.
	Data map[string]any `json:"data"`
}

// New builds an edge agent's event; it refuses a type or a subject outside the patterns, so a typo cannot reach a rule.
func New(edge, typ, subject, outcome, severity, reason string, at time.Time, ocsf map[string]any) (Event, error) {
	return NewFor("relikey-agent", "urn:relikey:edge:"+edge, typ, subject, outcome, severity, reason, at, ocsf)
}

// NewFor is New for another ReliKey solution (the fleet service, decision 0026), with its own name and source.
func NewFor(solution, source, typ, subject, outcome, severity, reason string, at time.Time, ocsf map[string]any) (Event, error) {
	if !Type.MatchString(typ) {
		return Event{}, fmt.Errorf("event type %q is not relikey.<noun>.<verb>.v<n>", typ)
	}
	if !entity.MatchString(subject) {
		return Event{}, fmt.Errorf("subject %q is not an entity id (<kind>:<edge>/<name>)", subject)
	}
	ts := at.UTC().Format(time.RFC3339Nano)
	data := map[string]any{"time": at.UnixMilli()}
	for k, v := range ocsf {
		data[k] = v
	}
	return Event{SpecVersion: "1.0", ID: uuid7(at), Source: source, Type: typ, Subject: subject,
		Time: ts, DataContentType: "application/json", TS: ts, Solution: solution, Name: typ,
		Outcome: outcome, Severity: severity, Reason: reason, Entity: subject, Data: data}, nil
}

var entity = regexp.MustCompile(`^[a-z][a-z-]*:[^/\s]+/\S+$`)

// uuid7 is a time-ordered id (RFC 9562): 48 bits of milliseconds, then random bits.
func uuid7(at time.Time) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(at.UnixMilli())<<16)
	_, _ = rand.Read(b[6:])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Writer writes events as JSON lines, one Write per line, safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	W  io.Writer
}

func (w *Writer) Emit(e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.W.Write(append(b, '\n'))
}

// SPDX-License-Identifier: EUPL-1.2

package events

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// The platform's alert-event contract: required fields and its event-name pattern.
var platformEvent = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){1,4}$`)

func TestALineIsACloudEventAndAPlatformEvent(t *testing.T) {
	ev, err := New("edge-a", "relikey.account.created.v1", "account:edge-a/ann", Success, Info, "applied", at,
		map[string]any{"class_uid": 3001})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	(&Writer{W: &buf}).Emit(ev)
	line := buf.String()
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		t.Fatalf("not one line: %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"specversion", "id", "source", "type", "subject", "time", "data", "ts", "solution", "event", "outcome", "entity"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s in %s", k, line)
		}
	}
	// CloudEvents extension attribute names are lower-case letters and digits only.
	for k := range m {
		if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(k) {
			t.Fatalf("attribute %q is not a valid CloudEvents name", k)
		}
	}
	if !platformEvent.MatchString(m["event"].(string)) {
		t.Fatalf("event %q breaks the platform's pattern", m["event"])
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(ev.ID) {
		t.Fatalf("id %s is not a UUIDv7", ev.ID)
	}
	if data := m["data"].(map[string]any); data["class_uid"] != float64(3001) || data["time"] != float64(at.UnixMilli()) {
		t.Fatalf("data %v", data)
	}
}

func TestMalformedTypesAndSubjectsAreRefused(t *testing.T) {
	for _, typ := range []string{"keyclerk.account.created.v1", "relikey.account.created", "relikey.Account.created.v1",
		"relikey.account.role-granted.v1"} {
		if _, err := New("e", typ, "account:e/ann", Success, Info, "", at, nil); err == nil {
			t.Fatalf("type %q accepted", typ)
		}
	}
	for _, sub := range []string{"ann", "account:e", "account:/ann", "Account:e/ann", "account:e/an n"} {
		if _, err := New("e", "relikey.account.created.v1", sub, Success, Info, "", at, nil); err == nil {
			t.Fatalf("subject %q accepted", sub)
		}
	}
}

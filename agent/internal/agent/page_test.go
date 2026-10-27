// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThePageShowsLeasesAndHealth(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	st := Status{Edge: "plant-a", Mode: Enforce, Updated: now, Started: now.Add(-time.Hour), PullsOK: 9, Serial: 7,
		AppliedSerial: 7, Plan: "in step", Leases: []LeaseView{{ID: "L-1", Person: "idp:ann", Username: "ann",
			Role: "operator", Target: "plc-ssh", Class: "low", Ends: now.Add(90 * time.Minute), Email: true}},
		Drift: []string{"lease L-9 carries no e-mail <script>"}}
	b, err := RenderPage(st, now)
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, want := range []string{"Edge plant-a", "Healthy", "ann", "operator", "plc-ssh", "1h 30m", "&lt;script&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if !strings.Contains(page, `content="default-src 'none';`) {
		t.Error("the page carries no content security policy")
	}
	if strings.Contains(page, "<script>") {
		t.Fatal("text from a bundle reached the page unescaped")
	}
	st.Ended = true
	if b, _ := RenderPage(st, now); !strings.Contains(string(b), "Needs attention") {
		t.Fatal("an ended edge shows healthy")
	}
}

// The page's mark is the brand's small mark: the paths in page.go are the ones brand/build_mark.py writes. A change
// to the brand that is not carried here fails this test (and the other way round).
func TestThePageMarkIsTheBrandMark(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "brand", "mark", "geometry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct{ Bowl, LegInk, Blade string }
	if err := json.Unmarshal(raw, &g, json.MatchCaseInsensitiveNames(true)); err != nil {
		t.Fatal(err)
	}
	var leg struct {
		LegInk string `json:"leg_ink"`
	}
	_ = json.Unmarshal(raw, &leg)
	for name, pair := range map[string][2]string{"bowl": {markBowl, g.Bowl}, "leg_ink": {markLeg, leg.LegInk},
		"blade": {markBlade, g.Blade}} {
		if pair[0] != pair[1] {
			t.Errorf("%s: page.go has %q, the brand has %q; copy the brand's path into page.go", name, pair[0], pair[1])
		}
	}
	b, err := RenderPage(Status{Edge: "plant-a", Mode: Enforce}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	// html/template writes the URL's "+" as the entity &#43;, which browsers decode back.
	for _, want := range []string{`<link rel="icon" type="image/svg+xml" href="data:image/svg&#43;xml,`, `aria-label="ReliKey"`,
		`class="a" d="` + markBlade} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(page, "ZgotmplZ") {
		t.Fatal("html/template refused the favicon URL")
	}
}

func TestMetricsArePrometheusTextAndCarryTheHealth(t *testing.T) {
	st := Status{PullsOK: 3, LiveLeases: 2}
	out := string(Metrics(st, nil))
	for _, want := range []string{"# TYPE relikey_agent_healthy gauge\nrelikey_agent_healthy 1\n",
		"relikey_agent_pulls_ok_total 3\n", "relikey_agent_live_leases 2\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if !strings.Contains(string(Metrics(st, []string{"stale"})), "relikey_agent_healthy 0\n") {
		t.Error("an unhealthy status must say 0")
	}
}

// A name from outside ReliKey cannot rearrange the page: direction and invisible characters show as a mark (A3).
func TestOutsideTextCannotRearrangeThePage(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	st := Status{Edge: "plant-a", Mode: Enforce, Updated: now, Started: now, Leases: []LeaseView{{ID: "L-1", Username: "ann\u202eevil", Role: "op", Target: "t", Class: "low", Ends: now.Add(time.Hour)}},
		Drift: []string{"account root\u200b is not managed"}}
	b, _ := RenderPage(st, now)
	for _, bad := range []string{"\u202e", "\u200b"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("%q reached the page", bad)
		}
	}
	if !strings.Contains(string(b), "ann\ufffdevil") {
		t.Error("the hidden character is not shown as a mark")
	}
}

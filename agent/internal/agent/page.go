// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"relikey/agent/internal/kcedge"
)

// LeaseView is a live lease as the status shows it.
type LeaseView struct {
	ID       string    `json:"id"`
	Person   string    `json:"person"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	Target   string    `json:"target"`
	Class    string    `json:"class"`
	Ends     time.Time `json:"ends"`
	Email    bool      `json:"email"` // whether SSO sign-in can be bound
}

func leaseViews(ls []kcedge.Lease) []LeaseView {
	out := make([]LeaseView, 0, len(ls))
	for _, l := range ls {
		out = append(out, LeaseView{ID: l.LeaseID, Person: l.Person, Username: l.Username, Role: l.Role, Target: l.Target,
			Class: l.Class, Ends: l.Ends, Email: l.Email != ""})
	}
	slices.SortFunc(out, func(a, b LeaseView) int { return a.Ends.Compare(b.Ends) })
	return out
}

// Health lists what is wrong, each with what fixes it; empty means healthy. The same
// rules drive `relikey-agent status` (the canary gate) and the status page.
func (st Status) Health(now time.Time, maxStreak int, maxAge time.Duration) []string {
	var bad []string
	if st.NonEmptyStreak > maxStreak {
		bad = append(bad, fmt.Sprintf("a plan has been left over for %d ticks (max %d): in shadow mode the new version "+
			"disagrees with the enforcing one; in enforce mode Warpgate refuses the changes (the agent's log names them)",
			st.NonEmptyStreak, maxStreak))
	}
	if age := now.Sub(st.Updated); age > maxAge {
		bad = append(bad, fmt.Sprintf("the status is %v old: the agent is not running its loop; read its log, "+
			"then restart it", age.Round(time.Second)))
	}
	if st.PullsOK == 0 && st.PullsFailed > 0 {
		bad = append(bad, "no pull has succeeded: check the network path to the desk and the enrolment key")
	}
	if st.Ended {
		bad = append(bad, "the desk ended this edge: it grants nothing until it is enrolled again")
	}
	return bad
}

var page = template.Must(template.New("status").Funcs(template.FuncMap{
	"left": func(t, now time.Time) string {
		d := t.Sub(now).Round(time.Minute)
		switch {
		case d <= 0:
			return "ending"
		case d < time.Hour:
			return fmt.Sprintf("%dm", int(d.Minutes()))
		case d < 48*time.Hour:
			return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
		}
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	},
	// bar is where a lease ends on the eight-hour board, in steps of five percent: a class, not a style attribute.
	"bar": func(t, now time.Time) int {
		f := float64(t.Sub(now)) / float64(boardSpan)
		return int(min(max(f, 0.02), 1)*20+0.5) * 5
	},
	"beyond": func(t, now time.Time) bool { return t.Sub(now) > boardSpan },
	"clock":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04Z") },
	"hhmm":   func(t time.Time) string { return t.UTC().Format("15:04Z") },
	"mib":    func(b uint64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) },
	"pct": func(a, b int64) string {
		if a+b == 0 {
			return "-"
		}
		return fmt.Sprintf("%.0f%%", 100*float64(a)/float64(a+b))
	},
	"plain": plain,
	// fixed tells a note the agent acted on (it ends in "reset") from one that needs a person.
	"fixed": func(s string) bool { return strings.HasSuffix(s, ": reset") },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="15"><title>ReliKey edge {{.S.Edge}}</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<link rel="icon" type="image/svg+xml" href="{{.Favicon}}">
<style>
:root{--bg:#f2f4f7;--card:#fff;--ink:#17142b;--soft:#5b5f72;--line:#d9dde5;--ok:#18794e;--okbg:#e6f4ec;--warn:#9a5b00;--warnbg:#fdf1dc;--bad:#b42318;--badbg:#fdecea;--key:#c85d16}
@media (prefers-color-scheme:dark){:root{--bg:#0f1420;--card:#171d2b;--ink:#f4f5f8;--soft:#a3abbd;--line:#2c3448;--ok:#4cc38a;--okbg:#10291d;--warn:#f0b24a;--warnbg:#2c2210;--bad:#ff6b5e;--badbg:#311613;--key:#f0954f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "IBM Plex Sans",ui-sans-serif,system-ui,"Segoe UI",sans-serif;font-variant-numeric:tabular-nums}
main{max-width:980px;margin:0 auto;padding:22px 16px 40px}
header{display:flex;align-items:center;gap:12px}header svg{width:34px;height:34px;flex:none}.i{fill:var(--ink)}.a{fill:var(--key)}
h1{font-size:22px;margin:0;font-weight:650}h1 span{color:var(--soft);font-weight:500;font-size:15px;margin-left:8px}
.lamp{display:flex;gap:14px;align-items:flex-start;margin:16px 0 24px;padding:12px 16px;border-left:6px solid;background:var(--card)}
.lamp b{display:block;font-size:17px}.lamp p,.lamp ul{margin:2px 0 0;color:var(--ink)}.lamp ul{padding-left:18px}
.lamp.ok{border-color:var(--ok)}.lamp.ok b{color:var(--ok)}.lamp.warn{border-color:var(--warn);background:var(--warnbg)}.lamp.warn b{color:var(--warn)}
.lamp.bad{border-color:var(--bad);background:var(--badbg)}.lamp.bad b{color:var(--bad)}
h2{font-size:17px;margin:0 0 4px;font-weight:650}.sub{color:var(--soft);margin:0 0 10px}
.board{background:var(--card);border:1px solid var(--line)}
.scale,.row{display:grid;grid-template-columns:minmax(200px,34%) 1fr;align-items:center}
.scale{color:var(--soft);font-size:12px;border-bottom:1px solid var(--line)}.scale span{padding:6px 14px}
.hours{display:flex;justify-content:space-between;padding:6px 0 6px 0;border-left:2px solid var(--key)}.hours i{font-style:normal;padding:0 6px}
.row{border-bottom:1px solid var(--line);min-height:62px}.row:last-child{border-bottom:0}
.who{padding:8px 14px}.who b{font-size:16px}.who div{color:var(--soft);font-size:13px}.who code{color:var(--ink)}
.track{position:relative;height:100%;min-height:62px;border-left:2px solid var(--key);background:repeating-linear-gradient(to right,transparent 0 calc(12.5% - 1px),var(--line) calc(12.5% - 1px) 12.5%)}
.track i{position:absolute;left:0;top:50%;height:14px;margin-top:-7px;background:var(--ok)}
.elevated .track i{background:var(--warn)}.privileged .track i{background:var(--bad)}
.track em{position:absolute;top:50%;margin-top:-11px;font-style:normal;font-weight:650;font-size:15px;padding-left:8px;white-space:nowrap}
.track em.in{transform:translateX(-100%);padding:0 10px 0 0;color:var(--card)}.track .far::after{content:" and more";font-weight:500}
.cls{font-weight:650}.low .cls{color:var(--ok)}.elevated .cls{color:var(--warn)}.privileged .cls{color:var(--bad)}
.tag{margin-left:6px;padding:0 7px;font-size:12px;font-weight:650;color:var(--warn);border:1px solid var(--warn)}
code{font:13px ui-monospace,Consolas,monospace}.none{padding:16px 14px;color:var(--soft)}
.agent{margin:26px 0 0;color:var(--soft)}.agent b{color:var(--ink);font-weight:650}
h3{font-size:15px;margin:22px 0 6px}ul.notes{margin:0;padding-left:18px}ul.notes li{margin:4px 0}
.fix::marker{color:var(--ok)}.ask::marker{color:var(--warn)}.fix span,.ask span{font-weight:650}.fix span{color:var(--ok)}.ask span{color:var(--warn)}
footer{margin-top:22px;color:var(--soft);font-size:12px}
@media (max-width:640px){.scale span{display:none}.scale,.row{grid-template-columns:1fr}.row{padding-bottom:8px}.track{min-height:34px;margin:0 14px}.hours{margin:0 14px}}
{{range .Steps}}.w{{.}}{width:{{.}}%}.l{{.}}{left:{{.}}%}{{end}}
</style></head><body><main>
<header>{{.Mark}}<h1>Edge {{.S.Edge}}<span>{{.S.Mode}} mode</span></h1></header>
{{if .Bad}}<div class="lamp bad"><div><b>Needs attention</b><ul>{{range .Bad}}<li>{{plain .}}</li>{{end}}</ul></div></div>
{{else if .S.ClockSkewed}}<div class="lamp warn"><div><b>Clock skew</b><p>This edge's clock disagrees with the desk's; leases run on the trusted clock until they agree.</p></div></div>
{{else}}<div class="lamp ok"><div><b>Healthy</b><p>In step with bundle {{.S.AppliedSerial}}, nothing left to apply.</p></div></div>{{end}}
<h2>Who can reach what</h2><p class="sub">{{len .S.Leases}} live lease{{if ne (len .S.Leases) 1}}s{{end}}, as of {{hhmm .Now}}. Each bar ends when that access ends.</p>
<div class="board"><div class="scale"><span>Person and target</span><div class="hours"><i>now</i><i>+2h</i><i>+4h</i><i>+6h</i><i>+8h</i></div></div>
{{range .S.Leases}}<div class="row {{.Class}}"><div class="who"><b>{{plain .Username}}</b>{{if not .Email}}<span class="tag" title="no verified e-mail: SSO sign-in cannot be bound">no SSO</span>{{end}}
<div><span class="cls">{{plain .Class}}</span>, {{plain .Role}} on <code>{{plain .Target}}</code></div></div>
<div class="track" title="ends {{clock .Ends}}, person {{plain .Person}}"><i class="w{{bar .Ends $.Now}}"></i><em class="l{{bar .Ends $.Now}}{{if ge (bar .Ends $.Now) 70}} in{{end}}{{if beyond .Ends $.Now}} far{{end}}">{{left .Ends $.Now}}</em></div></div>
{{else}}<div class="none">No lease is live: no one can reach a target through this edge.</div>{{end}}</div>
<p class="agent">Bundle <b>{{.S.Serial}}</b> (applied {{.S.AppliedSerial}}), pulls <b>{{pct .S.PullsOK .S.PullsFailed}}</b> ok ({{.S.PullsFailed}} failed), plan left over <b>{{.S.PlanActions}}</b> (streak {{.S.NonEmptyStreak}}), refused bundles <b>{{.S.Refused}}</b>, memory <b>{{mib .S.HeapAlloc}}</b>.</p>
{{if or .S.Drift .S.LastFailure .S.LastRefusal}}<h3>Drift and notes</h3><ul class="notes">
{{if .S.LastFailure}}<li class="ask"><span>Needs a person:</span> last failure <code>{{plain .S.LastFailure}}</code></li>{{end}}
{{if .S.LastRefusal}}<li class="ask"><span>Needs a person:</span> last refused bundle <code>{{plain .S.LastRefusal}}</code></li>{{end}}
{{range .S.Drift}}<li class="{{if fixed .}}fix"><span>Fixed by the agent:</span>{{else}}ask"><span>Needs a person:</span>{{end}} {{plain .}}</li>{{end}}</ul>{{end}}
<footer>{{.S.Version}}, updated {{clock .S.Updated}}, started {{clock .S.Started}}; {{.S.Ticks}} ticks, {{.S.Executed}} actions, {{.S.Failures}} failed. Written by the agent when it changes and at least every minute; it serves nothing.</footer>
</main></body></html>
`))

// The small ReliKey mark (no connector pins: it is shown at 36 px and as a favicon), copied from the brand's master
// geometry, brand/mark/geometry.json; TestThePageMarkIsTheBrandMark fails when the two drift apart. Inline, because
// the page is a file on an edge that may be offline: it loads nothing.
const (
	markBowl  = "M13 8h20a14 14 0 0 1 0 28H21v20h-8zM21 16v12h12a6 6 0 0 0 0-12z"
	markLeg   = "M25 31L34 31L38.68 40L29.68 40z"
	markBlade = "M29.68 40L38.68 40L40.24 43L44.74 43L46.82 47L42.32 47L43.88 50L48.38 50L50.46 54L45.96 54L47 56L38 56z"
)

var (
	pageMark = template.HTML(`<svg viewBox="0 0 64 64" role="img" aria-label="ReliKey"><path class="i" fill-rule="evenodd" d="` +
		markBowl + `"/><path class="i" d="` + markLeg + `"/><path class="a" d="` + markBlade + `"/></svg>`)
	// The favicon as the brand builds it: the small mark in white and the dark-theme orange on the ink plate.
	pageFavicon = template.URL("data:image/svg+xml," + url.PathEscape(`<svg xmlns="http://www.w3.org/2000/svg" `+
		`viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#17142b"/><g transform="translate(32 32) `+
		`scale(0.86) translate(-32 -32)"><path fill="#fff" fill-rule="evenodd" d="`+markBowl+`"/><path fill="#fff" d="`+
		markLeg+`"/><path fill="#f0954f" d="`+markBlade+`"/></g></svg>`))
)

// plain shows text from outside ReliKey (usernames, roles, targets, account names in drift notes) as it is:
// control, format and direction characters (bidi overrides, zero-width marks) become a visible U+FFFD, so a name
// cannot reverse, hide or fake the text around it on the page (GUI red team 2026-10-25, A3). Escaping stays
// html/template's.
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return utf8.RuneError
		}
		return r
	}, s)
}

// boardSpan is how far ahead the lease board looks; barSteps are its bar widths and label offsets (classes w0..w100,
// l0..l100).
const boardSpan = 8 * time.Hour

var barSteps = func() []int {
	var s []int
	for w := 0; w <= 100; w += 5 {
		s = append(s, w)
	}
	return s
}()

// RenderPage is the status page for a status, as of now.
func RenderPage(st Status, now time.Time) ([]byte, error) {
	var b bytes.Buffer
	err := page.Execute(&b, struct {
		S       Status
		Now     time.Time
		Bad     []string
		Mark    template.HTML
		Favicon template.URL
		Steps   []int
	}{st, now, st.Health(now, 2, 2*time.Minute), pageMark, pageFavicon, barSteps})
	return b.Bytes(), err
}

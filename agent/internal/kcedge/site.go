// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SiteFormat is the statement a site's physical key and a node sign over the same bytes (edge protocol 1.5 section
// 14, KeyClerk decision 0027): a replacement that runs on a dead edge's cached bundle (provisional). From edge
// protocol 1.6 a node made active by hand (promotion, section 7.3) is SiteFormatV2.
const SiteFormat = "kc-edge-site-v1"

// SiteFormatV2 is a promotion from edge protocol 1.6: it carries not_after, at most SiteMaxHours after at, so a
// statement found later cannot promote the node again.
const SiteFormatV2 = "kc-edge-site-v2"

// SiteMaxHours is a promotion statement's longest life: it promotes once, soon.
const SiteMaxHours = 24

// SiteFormatFor is the format a statement of this purpose is signed under (keyclerk.edge_relay.site_format).
func SiteFormatFor(purpose string) string {
	if purpose == "promotion" {
		return SiteFormatV2
	}
	return SiteFormat
}

// SitePurposes are the two things a site statement can say; the purpose is inside the signed bytes, so a statement
// made for one never serves as the other.
var SitePurposes = []string{"provisional", "promotion"}

var (
	siteFields   = []string{"at", "edge", "format", "node_key", "purpose", "reason", "site_key"}
	siteFieldsV2 = []string{"at", "edge", "format", "node_key", "not_after", "purpose", "reason", "site_key"}
)

// VerifySite is keyclerk.edge_relay.verify_site: a site statement for this edge and this purpose, signed by exactly
// the pinned site key and the node it names. v is the multi-signed object as parsed JSON. A promotion is
// SiteFormatV2: its not_after is after its at and at most SiteMaxHours later, and, unless now is zero, not passed at
// now (the caller's trusted time).
func VerifySite(v Value, siteKey, edge, purpose string, now time.Time) (Object, error) {
	if !slices.Contains(SitePurposes, purpose) {
		return nil, fmt.Errorf("purpose: %s", strings.Join(SitePurposes, " or "))
	}
	var node, format string
	if o, ok := v.(Object); ok {
		if b64, ok := o["bytes"].(string); ok {
			if raw, err := rawBytes(b64); err == nil {
				if body, err := parseSigned(raw); err == nil {
					node, _ = body["node_key"].(string)
					format, _ = body["format"].(string)
				}
			}
		}
	}
	if !hex64.MatchString(node) {
		return nil, errors.New("a site statement names the node's 64-hex enrolment key")
	}
	want := SiteFormatFor(purpose)
	if format != want {
		if purpose == "promotion" {
			return nil, errors.New("a promotion is kc-edge-site-v2 (edge protocol 1.6), with not_after: a statement " +
				"without one could promote the node again")
		}
		return nil, fmt.Errorf("a statement for %s is %s", purpose, want)
	}
	fields := siteFields
	if want == SiteFormatV2 {
		fields = siteFieldsV2
	}
	st, err := UnsealMulti(v, []string{siteKey, node}, want)
	if err != nil {
		return nil, err
	}
	if !sameKeys(st, fields) || st["site_key"] != siteKey {
		return nil, fmt.Errorf("a site statement is exactly {%s}, naming the pinned site key", strings.Join(fields, ", "))
	}
	if st["purpose"] != purpose {
		return nil, fmt.Errorf("a statement for %v is not one for %s", st["purpose"], purpose)
	}
	if st["edge"] != edge {
		return nil, errors.New("a site statement for another edge")
	}
	atS, _ := st["at"].(string)
	at, err := ParseTime(atS)
	if err != nil {
		return nil, err
	}
	reason, ok := st["reason"].(string)
	if n := len([]rune(reason)); !ok || n < 3 || n > 300 {
		return nil, errors.New("reason: 3 to 300 characters")
	}
	if want == SiteFormatV2 {
		naS, _ := st["not_after"].(string)
		na, err := ParseTime(naS)
		if err != nil {
			return nil, err
		}
		if !at.Before(na) || na.After(at.Add(SiteMaxHours*time.Hour)) {
			return nil, fmt.Errorf("not_after: after at, and at most %d hours later", SiteMaxHours)
		}
		if !now.IsZero() && now.After(na) {
			return nil, fmt.Errorf("the promotion statement expired at %s", naS)
		}
	}
	return st, nil
}

// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SiteFormat is the statement a site's physical key and a node sign over the same bytes (edge protocol 1.5 section
// 14, KeyClerk decision 0027): a replacement that runs on a dead edge's cached bundle (provisional) or a node made
// active by hand (promotion, section 7.3).
const SiteFormat = "kc-edge-site-v1"

// SitePurposes are the two things a site statement can say; the purpose is inside the signed bytes, so a statement
// made for one never serves as the other.
var SitePurposes = []string{"provisional", "promotion"}

var siteFields = []string{"at", "edge", "format", "node_key", "purpose", "reason", "site_key"}

// VerifySite is keyclerk.edge_relay.verify_site: a site statement for this edge and this purpose, signed by exactly
// the pinned site key and the node it names. v is the multi-signed object as parsed JSON.
func VerifySite(v Value, siteKey, edge, purpose string) (Object, error) {
	if !slices.Contains(SitePurposes, purpose) {
		return nil, fmt.Errorf("purpose: %s", strings.Join(SitePurposes, " or "))
	}
	var node string
	if o, ok := v.(Object); ok {
		if b64, ok := o["bytes"].(string); ok {
			if raw, err := rawBytes(b64); err == nil {
				if body, err := parseSigned(raw); err == nil {
					node, _ = body["node_key"].(string)
				}
			}
		}
	}
	if !hex64.MatchString(node) {
		return nil, errors.New("a site statement names the node's 64-hex enrolment key")
	}
	st, err := UnsealMulti(v, []string{siteKey, node}, SiteFormat)
	if err != nil {
		return nil, err
	}
	if !sameKeys(st, siteFields) || st["site_key"] != siteKey {
		return nil, fmt.Errorf("a site statement is exactly {%s}, naming the pinned site key", strings.Join(siteFields, ", "))
	}
	if st["purpose"] != purpose {
		return nil, fmt.Errorf("a statement for %v is not one for %s", st["purpose"], purpose)
	}
	if st["edge"] != edge {
		return nil, errors.New("a site statement for another edge")
	}
	at, _ := st["at"].(string)
	if _, err := ParseTime(at); err != nil {
		return nil, err
	}
	reason, ok := st["reason"].(string)
	if n := len([]rune(reason)); !ok || n < 3 || n > 300 {
		return nil, errors.New("reason: 3 to 300 characters")
	}
	return st, nil
}

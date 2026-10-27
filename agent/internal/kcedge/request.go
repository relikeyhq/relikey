// SPDX-License-Identifier: EUPL-1.2

package kcedge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// RequestContext names the signed-request format (KeyClerk interface section 3).
const RequestContext = "kc-edge-request-v2"

// RequestHeader is the header every call under /api/v1/edge/ carries.
const RequestHeader = "KeyClerk-Edge"

// RequestMessage is what the enrolment key signs: context, edge, METHOD, the path with
// its query exactly as sent, unix seconds, nonce and sha256 of the body, one per line.
func RequestMessage(edge, method, pathWithQuery string, seconds int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{RequestContext, edge, strings.ToUpper(method), pathWithQuery,
		strconv.FormatInt(seconds, 10), nonce, hex.EncodeToString(sum[:])}, "\n"))
}

// SignRequest returns the header value "edge;seconds;nonce;signature". Sign
// req.URL.RequestURI() of the request as built and the exact body bytes sent.
func SignRequest(key ed25519.PrivateKey, edge, method, pathWithQuery string, body []byte, seconds int64, nonce string) string {
	sig := ed25519.Sign(key, RequestMessage(edge, method, pathWithQuery, seconds, nonce, body))
	return edge + ";" + strconv.FormatInt(seconds, 10) + ";" + nonce + ";" + hex.EncodeToString(sig)
}

// NewNonce is 18 random bytes, base64url without padding (24 characters, inside the
// 16 to 64 the desk accepts).
func NewNonce() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return base64.RawURLEncoding.EncodeToString(b)
}

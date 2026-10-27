// SPDX-License-Identifier: EUPL-1.2

// Package httpx builds the agent's HTTP clients by the network rules in
// docs/go-engineering.md: one client per peer, timeouts on every phase, no
// redirects, no proxy unless configured, response bodies capped.
package httpx

import (
	"cmp"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Options for one peer.
type Options struct {
	Timeout time.Duration // whole request; 0 for streams
	// ResponseHeader is how long to wait for the response headers (default 20 s); a long-poll's come after its hold.
	ResponseHeader time.Duration
	// Exactly one of RootCAs (verify the chain and the name) and PinSHA256 (the leaf
	// certificate's SHA-256, for a loopback service with its own certificate).
	RootCAs    *x509.CertPool
	PinSHA256  string
	ServerName string
	Proxy      *url.URL // nil: never a proxy (HTTP_PROXY is ignored)
	MinTLS13   bool
	// RequireHybrid allows only TLS 1.3 with the X25519MLKEM768 hybrid key exchange: a peer that cannot do it is
	// refused, never served classically (decision 0022 A3, for links whose both ends are ReliKey's).
	RequireHybrid bool
	// Group, when set, records the key exchange group each handshake negotiated (the agent's status shows it).
	Group *Group
}

// Group is the key exchange group the last handshake to one peer negotiated.
type Group struct{ v atomic.Value }

func (g *Group) set(id tls.CurveID) { g.v.Store(id.String()) }

// String is the group's name, or "" before the first handshake.
func (g *Group) String() string {
	if g == nil {
		return ""
	}
	s, _ := g.v.Load().(string)
	return s
}

// ErrRedirect: no peer of the agent redirects, and following one would send the
// admin token or a signed request to another URL.
var ErrRedirect = errors.New("redirect refused")

// New returns a client for one peer.
func New(o Options) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}
	if o.MinTLS13 {
		tc.MinVersion = tls.VersionTLS13
	}
	switch {
	case o.PinSHA256 != "" && o.RootCAs == nil:
		pin := strings.ToLower(strings.ReplaceAll(o.PinSHA256, ":", ""))
		if len(pin) != 64 {
			return nil, errors.New("the certificate pin is a SHA-256 in hex (64 characters)")
		}
		// The chain is not verified by name or CA; the pin replaces it and is checked on
		// every connection (VerifyConnection runs with InsecureSkipVerify too).
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate presented")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("certificate %x does not match the pinned one", sum[:8])
			}
			return nil
		}
	case o.RootCAs != nil && o.PinSHA256 == "":
		tc.RootCAs = o.RootCAs
	default:
		return nil, errors.New("give either a CA or a certificate pin for this peer")
	}
	if o.RequireHybrid {
		tc.MinVersion = tls.VersionTLS13
		tc.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	}
	if o.RequireHybrid || o.Group != nil {
		pinCheck := tc.VerifyConnection
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if pinCheck != nil {
				if err := pinCheck(cs); err != nil {
					return err
				}
			}
			if o.RequireHybrid && cs.CurveID != tls.X25519MLKEM768 {
				return fmt.Errorf("the peer negotiated %v, not the hybrid post-quantum X25519MLKEM768 this link requires "+
					"(decision 0022): upgrade the peer's TLS stack, or check for TLS inspection in between", cs.CurveID)
			}
			if o.Group != nil {
				o.Group.set(cs.CurveID)
			}
			return nil
		}
	}
	var proxy func(*http.Request) (*url.URL, error)
	if o.Proxy != nil {
		proxy = http.ProxyURL(o.Proxy)
	}
	tr := &http.Transport{
		Proxy:                  proxy,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  cmp.Or(o.ResponseHeader, 20*time.Second),
		ExpectContinueTimeout:  time.Second,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
	}, nil
}

// ErrTooLarge is a response body over its limit (LimitReader alone would truncate).
var ErrTooLarge = errors.New("response body over its limit")

// ReadAll reads at most limit bytes and refuses more; it always drains and closes.
func ReadAll(r io.ReadCloser, limit int64) ([]byte, error) {
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
		return nil, ErrTooLarge
	}
	return b, nil
}

// CertSHA256 is the pin for a PEM certificate file's first certificate (installation).
func CertSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

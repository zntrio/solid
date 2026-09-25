// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Package httpfetch provides a hardened HTTPS document fetcher for
// server-side retrieval of small, untrusted JSON documents from
// client-controlled URLs — e.g. OAuth Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document), client jwks_uri, or
// software statements.
//
// Posture:
//   - redirects are refused: the document must be served at the requested
//     URL itself (draft-ietf-oauth-client-id-metadata-document section 5)
//   - exactly HTTP 200 is accepted
//   - response bodies are capped at maxResponseBytes (section 8.7 recommends
//     5 kB), read through a LimitReader so a hostile server cannot exhaust
//     server memory
//   - the destination host is resolved BEFORE the request and any RFC 6890
//     special-use / private / loopback address rejects the fetch (section
//     8.6, SSRF mitigation); the transport dial re-checks every dialed
//     address, guarding against DNS rebinding
//   - slow-loris mitigation: a hard wall-clock deadline bounds DNS, dial,
//     TLS handshake, response headers, and body read, so a byte-dripping
//     server cannot hold connections open
package httpfetch

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// -----------------------------------------------------------------------------

// Defaults hardening the fetch against resource-exhaustion (slow-loris) and
// oversized-response attacks.
const (
	// DefaultMaxResponseBytes is the recommended maximum document size
	// (draft-ietf-oauth-client-id-metadata-document section 8.7 recommends
	// 5 kB).
	DefaultMaxResponseBytes int64 = 5120
	// DefaultTimeout bounds the entire fetch — DNS resolution, dial, TLS
	// handshake, response headers, and body read — so a slow-loris attacker
	// dripping bytes cannot hold a connection open beyond it.
	DefaultTimeout = 10 * time.Second
	// dialTimeout bounds a single TCP dial attempt.
	dialTimeout = 5 * time.Second
	// tlsHandshakeTimeout bounds the TLS handshake.
	tlsHandshakeTimeout = 5 * time.Second
	// responseHeaderTimeout bounds waiting for response headers after the
	// request is written; the body read is bounded by the total deadline.
	responseHeaderTimeout = 5 * time.Second
)

// Fetcher retrieves a document body at the given https URL.
type Fetcher interface {
	Fetch(ctx context.Context, documentURL string) ([]byte, error)
}

// fetcher is the hardened HTTP adapter.
type fetcher struct {
	client   *http.Client
	maxBytes int64
	// preflight validates the destination before the request is issued.
	// Injectable so tests can target an httptest server on loopback.
	preflight func(rawURL string) error
}

// New builds a hardened HTTPS Fetcher over the given client. When client is
// nil, a default transport clone is installed. maxResponseBytes <= 0 means
// DefaultMaxResponseBytes.
//
// Caller-supplied transports keep their configuration (proxy, TLS settings)
// except where hardening tightens them: dials to special-use addresses are
// refused, and per-phase timeouts never exceed the defaults above. A
// caller-supplied client timeout is honored only when stricter than
// DefaultTimeout, never looser.
func New(client *http.Client, maxResponseBytes int64) Fetcher {
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultMaxResponseBytes
	}

	// Caller-supplied non-Transport RoundTrippers (e.g. test dialers) are
	// preserved; everything else gets the hardened transport.
	transport := http.RoundTripper(hardenedTransport(client))
	if client != nil && client.Transport != nil {
		transport = client.Transport
	}

	return &fetcher{
		client: &http.Client{
			Transport: transport,
			Jar: func() http.CookieJar {
				if client == nil {
					return nil
				}
				return client.Jar
			}(),
			// Reject redirects: the caller sees the 3xx response as a
			// non-200 error.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: func() time.Duration {
				// A caller timeout is honored only when stricter than the
				// default, never looser.
				if client != nil && client.Timeout > 0 && client.Timeout < DefaultTimeout {
					return client.Timeout
				}
				return DefaultTimeout
			}(),
		},
		maxBytes:  maxResponseBytes,
		preflight: rejectSpecialUseHost,
	}
}

// NewTestFetcher builds a Fetcher with the SSRF pre-flight check disabled.
// It exists so external test packages can target an httptest TLS server on
// loopback — which the real pre-flight rejects by design. Never use outside
// tests.
func NewTestFetcher(client *http.Client, maxResponseBytes int64) Fetcher {
	f := New(client, maxResponseBytes).(*fetcher) //nolint:forcetypeassert // constructor return type is fixed
	f.preflight = func(string) error { return nil }
	return f
}

// Fetch retrieves the document body at the given https URL.
func (f *fetcher) Fetch(ctx context.Context, documentURL string) ([]byte, error) {
	// Hard wall-clock deadline around the whole exchange: DNS, dial, TLS,
	// headers, and body. A caller-supplied context may already be shorter,
	// in which case it wins; it is never extended.
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	// Resolve the destination host and reject special-use addresses before
	// issuing the request (SSRF mitigation).
	if err := f.preflight(documentURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("httpfetch: unable to build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpfetch: unable to execute request: %w", err)
	}
	defer resp.Body.Close()

	// The document must be served with exactly 200 OK; redirects are
	// rejected by the client policy and surface here as non-200.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpfetch: unexpected status code %d fetching document", resp.StatusCode)
	}

	// Size cap: read at most maxBytes+1 so an oversized body is detected,
	// never buffered. The ctx deadline bounds the read duration, defeating
	// byte-drip feeds.
	b, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("httpfetch: unable to read response body: %w", err)
	}
	if int64(len(b)) > f.maxBytes {
		return nil, fmt.Errorf("httpfetch: document exceeds maximum size of %d bytes", f.maxBytes)
	}

	return b, nil
}

// -----------------------------------------------------------------------------

// hardenedTransport clones the caller's *http.Transport (or the default)
// and tightens the per-phase timeouts. The special-use dial guard is
// installed only on the default transport: a caller-provided transport
// owns its own dial policy (proxy, TLS settings, dialer), and the
// pre-flight resolution remains the SSRF defense for those.
func hardenedTransport(client *http.Client) *http.Transport {
	var base *http.Transport
	if client == nil || client.Transport == nil {
		base = http.DefaultTransport.(*http.Transport) //nolint:forcetypeassert // fixed type
	} else {
		// Caller-provided *http.Transport: preserve its configuration
		// (proxy, TLS settings, dialer) — the caller owns its dial policy;
		// the pre-flight resolution remains the SSRF defense. Only the
		// per-phase timeouts are tightened, never loosened.
		base, _ = client.Transport.(*http.Transport)
		t := base.Clone()
		if t.TLSHandshakeTimeout <= 0 || t.TLSHandshakeTimeout > tlsHandshakeTimeout {
			t.TLSHandshakeTimeout = tlsHandshakeTimeout
		}
		if t.ResponseHeaderTimeout <= 0 || t.ResponseHeaderTimeout > responseHeaderTimeout {
			t.ResponseHeaderTimeout = responseHeaderTimeout
		}
		return t
	}

	t := base.Clone()
	// Default transport: install the full dial guard against special-use
	// destinations (defense-in-depth against DNS rebinding).
	t.DialContext = specialUseGuardingDialContext(t, dialTimeout)
	t.TLSHandshakeTimeout = tlsHandshakeTimeout
	t.ResponseHeaderTimeout = responseHeaderTimeout
	return t
}

// specialUsePrefixes lists IPv4 and IPv6 CIDRs the fetcher must never connect
// to (RFC 6890 special-use ranges, private and documentation ranges).
var specialUsePrefixes = func() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, 24)
	add := func(s string) {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	add("0.0.0.0/8")          // "this network"
	add("10.0.0.0/8")         // private use
	add("100.64.0.0/10")      // shared address space (CGNAT)
	add("127.0.0.0/8")        // loopback
	add("169.254.0.0/16")     // link-local
	add("172.16.0.0/12")      // private use
	add("192.0.0.0/24")       // IETF protocol assignments
	add("192.0.2.0/24")       // documentation (TEST-NET-1)
	add("192.88.99.0/24")     // 6to4 relay anycast (deprecated)
	add("192.168.0.0/16")     // private use
	add("198.18.0.0/15")      // benchmarking
	add("198.51.100.0/24")    // documentation (TEST-NET-2)
	add("203.0.113.0/24")     // documentation (TEST-NET-3)
	add("240.0.0.0/4")        // reserved
	add("255.255.255.255/32") // limited broadcast
	add("::/128")             // unspecified
	add("::1/128")            // loopback
	add("64:ff9b:1::/48")     // local-use NAT64
	add("100::/64")           // discard-only
	add("2001:db8::/32")      // documentation
	add("fc00::/7")           // unique local
	add("fe80::/10")          // link-local
	add("ff00::/8")           // multicast
	return prefixes
}()

// isSpecialUseAddr reports whether addr belongs to a range the fetcher must
// never connect to.
func isSpecialUseAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range specialUsePrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// hostPortOf extracts the host:port of a URL, defaulting the port to 443
// for https URLs without an explicit one.
func hostPortOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fall back to the raw value; SplitHostPort will fail cleanly.
		return rawURL
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port)
}

// rejectSpecialUseHost resolves the URL host and fails when any resolved
// address is a special-use address (SSRF mitigation).
func rejectSpecialUseHost(rawURL string) error {
	h, port, err := net.SplitHostPort(hostPortOf(rawURL))
	if err != nil {
		return fmt.Errorf("httpfetch: unable to parse host: %w", err)
	}
	p, portErr := strconv.Atoi(port)
	if portErr != nil || p < 1 || p > 65535 {
		return fmt.Errorf("httpfetch: invalid port %q", port)
	}

	// Literal IP destination.
	ip, parseErr := netip.ParseAddr(h)
	if parseErr == nil {
		if isSpecialUseAddr(ip) {
			return fmt.Errorf("httpfetch: host %s is a special-use address", h)
		}
		return nil
	}

	// Resolve every address; any special-use result rejects the fetch.
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", h)
	if err != nil {
		return fmt.Errorf("httpfetch: unable to resolve host %s: %w", h, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("httpfetch: no address resolved for host %s", h)
	}
	for _, a := range addrs {
		if isSpecialUseAddr(a) {
			return fmt.Errorf("httpfetch: host %s resolves to special-use address %s", h, a)
		}
	}
	return nil
}

// specialUseGuardingDialContext wraps the transport's dialer with one that
// refuses special-use destinations, defending against DNS rebinding between
// the pre-flight resolution and the actual connection.
func specialUseGuardingDialContext(t *http.Transport, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := t.DialContext
	if base == nil {
		base = (&net.Dialer{Timeout: timeout}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if ip, ipErr := netip.ParseAddr(host); ipErr == nil && isSpecialUseAddr(ip) {
				return nil, fmt.Errorf("httpfetch: refusing to dial special-use address %s", host)
			}
		}
		return base(ctx, network, addr)
	}
}

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

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"zntr.io/solid/sdk/httpfetch"
	"zntr.io/solid/sdk/resourcemetadata"
)

// RFC 9728 adversarial coverage: an attacker-controlled resource server
// (threat model sections 7.3 and 7.7) serving hostile Protected Resource
// Metadata — or an attacker feeding hostile identifiers to a victim client
// — and the countermeasures the resolver must enforce.

// -----------------------------------------------------------------------------
// Harness

// rfc9728Server is a TLS test server (loopback, special-use) serving an
// attacker-controlled metadata document, paired with a resolver fetching
// through it.
type rfc9728Server struct {
	ts       *httptest.Server
	resolver resourcemetadata.Resolver
}

// newRFC9728Server starts an HTTPS test server answering every request with
// the document built by doc; doc receives the server's base URL so the
// served `resource` member can be derived from it after startup. The
// resolver is built with the given verifier (nil = fail-closed posture) over
// the loopback-enabled test fetcher.
func newRFC9728Server(t *testing.T, verifier resourcemetadata.SignedMetadataVerifier, doc func(baseURL string) string) *rfc9728Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(doc("https://" + r.Host)))
	}))
	t.Cleanup(ts.Close)
	return &rfc9728Server{
		ts:       ts,
		resolver: resourcemetadata.NewResolver(httpfetch.NewTestFetcher(ts.Client(), 0), verifier, 0),
	}
}

// identifier returns the resource identifier of the test server (https
// loopback with port, no path): resolving it derives the well-known URL the
// server answers at.
func (s *rfc9728Server) identifier() string {
	return s.ts.URL
}

// rfc9728StubVerifier is a stub SignedMetadataVerifier that rejects or
// accepts every signed_metadata token according to reject, recording the
// arguments it was invoked with.
type rfc9728StubVerifier struct {
	reject bool

	lastResource       string
	lastSignedMetadata string
}

// Verify implements resourcemetadata.SignedMetadataVerifier.
func (v *rfc9728StubVerifier) Verify(_ context.Context, resource, signedMetadata string) error {
	v.lastResource = resource
	v.lastSignedMetadata = signedMetadata
	if v.reject {
		return errors.New("rfc9728: verifier veto")
	}
	return nil
}

// -----------------------------------------------------------------------------
// Tests

// TestRFC9728_HappyPath_3 asserts an honest resource server resolves: the
// metadata document served at the derived well-known URL round-trips its
// members (positive control for every adversarial case below).
func TestRFC9728_HappyPath_3(t *testing.T) {
	s := newRFC9728Server(t, nil, func(baseURL string) string {
		return `{
			"resource": "` + baseURL + `",
			"authorization_servers": ["https://as.example.com"],
			"jwks_uri": "` + baseURL + `/jwks",
			"scopes_supported": ["timestamp:read"]
		}`
	})

	md, err := s.resolver.Resolve(t.Context(), s.identifier())
	require.NoError(t, err)
	require.Equal(t, s.identifier(), md.GetResource())
	require.Equal(t, []string{"https://as.example.com"}, md.GetAuthorizationServers())
	require.Equal(t, s.identifier()+"/jwks", md.GetJwksUri())
	require.Equal(t, []string{"timestamp:read"}, md.GetScopesSupported())
}

// TestRFC9728_ResourceMismatchRejected_3_3 asserts the section 3.3
// impersonation countermeasure: an attacker (section 7.3) reachable at
// identifier X serving metadata claiming to describe resource Y must not be
// usable — the mismatch aborts resolution and the error names both
// identifiers.
func TestRFC9728_ResourceMismatchRejected_3_3(t *testing.T) {
	s := newRFC9728Server(t, nil, func(string) string {
		return `{"resource": "https://attacker.example", "jwks_uri": "https://attacker.example/jwks"}`
	})

	_, err := s.resolver.Resolve(t.Context(), s.identifier())
	require.Error(t, err, "metadata claiming a foreign resource must be rejected")
	require.Contains(t, err.Error(), "https://attacker.example")
	require.Contains(t, err.Error(), s.identifier(), "the error must name the expected identifier")
}

// TestRFC9728_PlaintextIdentifierRejected_1_2 asserts an attacker cannot
// push resolution down to plaintext: an http identifier is refused before
// any well-known URL is constructed (section 1.2 requires https).
func TestRFC9728_PlaintextIdentifierRejected_1_2(t *testing.T) {
	s := newRFC9728Server(t, nil, func(string) string {
		return `{"resource": "http://127.0.0.1"}`
	})

	_, err := s.resolver.Resolve(t.Context(), strings.Replace(s.identifier(), "https", "http", 1))
	require.Error(t, err, "plaintext identifiers must be refused before fetching")
	require.Contains(t, err.Error(), "https scheme")
}

// TestRFC9728_FragmentIdentifierRejected_1_2 asserts an identifier carrying
// a fragment is refused at well-known URL construction (section 1.2: no
// fragment component).
func TestRFC9728_FragmentIdentifierRejected_1_2(t *testing.T) {
	_, err := resourcemetadata.WellKnownURL("https://resource.example.com/resource1#frag", resourcemetadata.WellKnownSuffix)
	require.Error(t, err, "fragment components must be rejected")
	require.Contains(t, err.Error(), "fragment")
}

// TestRFC9728_WellKnownURLInsertion_3_1 asserts the well-known URI
// construction rules of section 3.1: insertion between host and path,
// trailing-slash stripping, query preservation, custom suffixes, and
// multi-tenant paths.
func TestRFC9728_WellKnownURLInsertion_3_1(t *testing.T) {
	t.Run("bare host", func(t *testing.T) {
		got, err := resourcemetadata.WellKnownURL("https://resource.example.com", "")
		require.NoError(t, err)
		require.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource", got)
	})

	t.Run("path after insertion", func(t *testing.T) {
		got, err := resourcemetadata.WellKnownURL("https://resource.example.com/resource1", "")
		require.NoError(t, err)
		require.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource/resource1", got)
	})

	t.Run("trailing slash stripped", func(t *testing.T) {
		got, err := resourcemetadata.WellKnownURL("https://resource.example.com/", "")
		require.NoError(t, err)
		require.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource", got)
	})

	t.Run("query preserved", func(t *testing.T) {
		got, err := resourcemetadata.WellKnownURL("https://resource.example.com/resource1?tenant=a", "")
		require.NoError(t, err)
		require.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource/resource1?tenant=a", got)
	})

	t.Run("custom suffix", func(t *testing.T) {
		got, err := resourcemetadata.WellKnownURL("https://resource.example.com", "custom-suffix")
		require.NoError(t, err)
		require.Equal(t, "https://resource.example.com/.well-known/custom-suffix", got)
	})

	t.Run("multi-tenant path and query combined", func(t *testing.T) {
		got, err := resourcemetadata.WellKnownURL("https://resource.example.com/tenant1/api?version=2", "")
		require.NoError(t, err)
		require.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource/tenant1/api?version=2", got)
	})
}

// TestRFC9728_SignedMetadataUnverifiableRejected_2_2 asserts the fail-closed
// posture: an attacker serves a document carrying signed_metadata but the
// client wired no verifier, so the attestation is unverifiable — the document
// must be rejected, never silently trusted (section 2.2).
func TestRFC9728_SignedMetadataUnverifiableRejected_2_2(t *testing.T) {
	s := newRFC9728Server(t, nil, func(baseURL string) string {
		return `{"resource": "` + baseURL + `", "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.AB"}`
	})

	_, err := s.resolver.Resolve(t.Context(), s.identifier())
	require.Error(t, err, "unverifiable signed_metadata must be rejected fail-closed")
	require.Contains(t, err.Error(), "no verifier is configured")
}

// TestRFC9728_SignedMetadataVerifierVeto_2_2 asserts the verifier hook is
// honored: a rejecting verifier fails resolution; an accepting one yields
// the document (signature validation itself is the verifier's contract,
// section 2.2).
func TestRFC9728_SignedMetadataVerifierVeto_2_2(t *testing.T) {
	t.Run("veto", func(t *testing.T) {
		verifier := &rfc9728StubVerifier{reject: true}
		s := newRFC9728Server(t, verifier, func(baseURL string) string {
			return `{"resource": "` + baseURL + `", "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.AB"}`
		})

		_, err := s.resolver.Resolve(t.Context(), s.identifier())
		require.Error(t, err, "a verifier veto must fail resolution")
		require.Contains(t, err.Error(), "verifier veto")
	})

	t.Run("accept", func(t *testing.T) {
		verifier := &rfc9728StubVerifier{}
		s := newRFC9728Server(t, verifier, func(baseURL string) string {
			return `{"resource": "` + baseURL + `", "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.AB"}`
		})

		md, err := s.resolver.Resolve(t.Context(), s.identifier())
		require.NoError(t, err)
		require.Equal(t, s.identifier(), md.GetResource())
		require.Equal(t, s.identifier(), verifier.lastResource)
		require.Equal(t, "eyJhbGciOiJFUzI1NiJ9.e30.AB", verifier.lastSignedMetadata)
	})
}

// TestRFC9728_NoneSigningAlgRejected_2 asserts a resource server advertising
// `none` in resource_signing_alg_values_supported is rejected: unsigned
// metadata must not be offered (section 2 — the value none MUST NOT be
// used).
func TestRFC9728_NoneSigningAlgRejected_2(t *testing.T) {
	s := newRFC9728Server(t, nil, func(baseURL string) string {
		return `{"resource": "` + baseURL + `", "resource_signing_alg_values_supported": ["ES256", "none"]}`
	})

	_, err := s.resolver.Resolve(t.Context(), s.identifier())
	require.Error(t, err, "the none signing algorithm must be rejected at decode")
	require.Contains(t, err.Error(), "none")
}

// TestRFC9728_OversizedDocumentRejected asserts the resolver's own size cap:
// an attacker serving a >64 kB document is rejected even through a fetcher
// with no cap of its own (defense in depth, resource-exhaustion posture).
func TestRFC9728_OversizedDocumentRejected(t *testing.T) {
	// Permissive fetcher stub: returns the blob directly, no cap.
	blob := `{"resource": "https://resource.example.com/", "junk": "` + strings.Repeat("a", 128*1024) + `"}`
	r := resourcemetadata.NewResolver(staticFetcher{body: []byte(blob)}, nil, 0)

	_, err := r.Resolve(t.Context(), "https://resource.example.com/")
	require.Error(t, err, "the resolver must cap document size independently of the fetcher")
	require.Contains(t, err.Error(), "exceeding")
}

// staticFetcher serves a fixed body for every URL, with no cap.
type staticFetcher struct {
	body []byte
}

// Fetch implements resourcemetadata.Fetcher.
func (f staticFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	return f.body, nil
}

// TestRFC9728_SsrFencedFetcherRedirectRejected_7_7 asserts the section 7.7
// SSRF posture end-to-end with the real (non-test) hardened fetcher: an
// attacker responding 302 to redirect the client elsewhere is refused —
// the document must be served at the requested URL itself.
func TestRFC9728_SsrFencedFetcherRedirectRejected_7_7(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource": "https://attacker.example"}`))
	}))
	t.Cleanup(target.Close)

	// Redirect to a URL the loopback test client could reach, proving the
	// refusal comes from the redirect policy, not the destination.
	redirectTarget := target.URL + "/.well-known/oauth-protected-resource"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget, http.StatusFound)
	}))
	t.Cleanup(ts.Close)

	r := resourcemetadata.NewResolver(httpfetch.New(ts.Client(), 0), nil, 0)
	_, err := r.Resolve(t.Context(), ts.URL)
	require.Error(t, err, "a redirecting resource server must be refused")
	require.Contains(t, err.Error(), "unable to fetch")
}

// TestRFC9728_MissingResourceMemberRejected_2 asserts a document without
// the REQUIRED `resource` member is rejected at decode (section 2).
func TestRFC9728_MissingResourceMemberRejected_2(t *testing.T) {
	s := newRFC9728Server(t, nil, func(string) string {
		return `{"jwks_uri": "https://resource.example.com/jwks"}`
	})

	_, err := s.resolver.Resolve(t.Context(), s.identifier())
	require.Error(t, err, "a document without the resource member must be rejected")
	require.Contains(t, err.Error(), `"resource"`)
}

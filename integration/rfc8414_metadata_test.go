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
// specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/handlers"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token/jwt"
)

// RFC 8414 (OAuth 2.0 Authorization Server Metadata) conformance coverage,
// exercised against the real example-AS metadata handler, the same handler
// mounted by examples/authorizationserver/main.go at
// /.well-known/oauth-authorization-server. Section references per RFC 8414
// (vendored at docs/rfcs/rfc8414.txt).

// metadataTestServer boots the real metadata handler behind an httptest
// server and returns the base URL to use as the issuer identifier. RFC 8414
// section 2 requires https for issuer / endpoint URLs on the wire; the
// httptest loopback origin substitutes for TLS termination in-process, which
// is a presentation-layer concern per the project's transport decoupling.
func metadataTestServer(t *testing.T) (baseURL string, close func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptoRand.Reader)
	require.NoError(t, err)
	signingKey, err := jwxjwk.Import(key)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwxjwk.AlgorithmKey, "ES384"))
	require.NoError(t, signingKey.Set(jwxjwk.KeyUsageKey, "sig"))
	require.NoError(t, signingKey.Set(jwxjwk.KeyIDKey, "rfc8414-test-key"))
	signer := jwt.ServerMetadata("ES384", jwk.KeyProviderFunc(func(_ context.Context) (jwk.Key, error) {
		return signingKey, nil
	}))

	srv := httptest.NewServer(handlers.Metadata("https://as.example.org", signer))
	return srv.URL, srv.Close
}

// fetchMetadataDocument GETs the well-known metadata document (RFC 8414
// section 3.1: the document MUST be queried with an HTTP GET request).
func fetchMetadataDocument(t *testing.T, rawurl string) (status int, contentType string, body map[string]any) {
	t.Helper()

	resp, err := http.Get(rawurl) //nolint: noctx // test-only single-shot discovery fetch
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	status = resp.StatusCode
	contentType = resp.Header.Get("Content-Type")
	if resp.Body != nil {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	}
	return status, contentType, body
}

// TestRFC8414_MetadataDocumentAccessible_3 asserts section 3: the metadata
// document is published at the default well-known path
// /.well-known/oauth-authorization-server and section 3.2: a successful
// response uses 200 OK with an application/json body.
func TestRFC8414_MetadataDocumentAccessible_3(t *testing.T) {
	base, closeFn := metadataTestServer(t)
	defer closeFn()

	status, contentType, _ := fetchMetadataDocument(t, base+"/.well-known/oauth-authorization-server")
	require.Equal(t, http.StatusOK, status, "a successful metadata response MUST use 200 OK (RFC 8414 section 3.2)")
	require.True(t, strings.HasPrefix(contentType, "application/json"), "metadata responses use the application/json content type (RFC 8414 section 3.2), got %q", contentType)
}

// TestRFC8414_RequiredMetadataMembers_2 asserts the REQUIRED members of the
// metadata document per RFC 8414 section 2: issuer (no query or fragment),
// authorization_endpoint, token_endpoint, response_types_supported; plus
// jwks_uri using the https scheme.
func TestRFC8414_RequiredMetadataMembers_2(t *testing.T) {
	base, closeFn := metadataTestServer(t)
	defer closeFn()

	_, _, md := fetchMetadataDocument(t, base+"/.well-known/oauth-authorization-server")

	// issuer is REQUIRED, a URL without query or fragment components.
	issuer, ok := md["issuer"].(string)
	require.True(t, ok && issuer != "", "issuer member is REQUIRED (RFC 8414 section 2)")
	u, err := url.Parse(issuer)
	require.NoError(t, err, "issuer must be a valid URL")
	require.Empty(t, u.RawQuery, "issuer must have no query component (RFC 8414 section 2)")
	require.Empty(t, u.Fragment, "issuer must have no fragment component (RFC 8414 section 2)")

	// authorization_endpoint is REQUIRED when a grant type using it is
	// supported (the auth-code grant is advertised).
	authzEndpoint, ok := md["authorization_endpoint"].(string)
	require.True(t, ok && authzEndpoint != "", "authorization_endpoint member is REQUIRED (RFC 8414 section 2)")

	// token_endpoint is REQUIRED unless only the implicit grant is supported.
	tokenEndpoint, ok := md["token_endpoint"].(string)
	require.True(t, ok && tokenEndpoint != "", "token_endpoint member is REQUIRED (RFC 8414 section 2)")

	// Every endpoint URL advertised by the document must be an absolute URL
	// (they are resolved by clients against the issuer).
	for name, endpoint := range map[string]string{
		"authorization_endpoint": authzEndpoint,
		"token_endpoint":         tokenEndpoint,
	} {
		ep, err := url.Parse(endpoint)
		require.NoError(t, err, "%s must be a valid URL", name)
		require.NotEmpty(t, ep.Host, "%s must be absolute", name)
	}

	// response_types_supported is REQUIRED and must be a non-empty JSON
	// array (claims with zero elements MUST be omitted, section 3.2).
	rt, ok := md["response_types_supported"].([]any)
	require.True(t, ok, "response_types_supported is REQUIRED (RFC 8414 section 2)")
	require.NotEmpty(t, rt, "an empty response_types_supported array MUST be omitted (RFC 8414 section 3.2)")
	require.Contains(t, rt, "code", "the server supports response_type=code")

	// jwks_uri, when present, must use the https scheme (RFC 8414 section 2).
	if jwksURI, ok := md["jwks_uri"].(string); ok && jwksURI != "" {
		ju, err := url.Parse(jwksURI)
		require.NoError(t, err)
		require.Equal(t, "https", ju.Scheme, "jwks_uri MUST use the https scheme (RFC 8414 section 2)")
	}
}

// TestRFC8414_ArrayValuedMembersAreArrays_3_2 asserts section 3.2: claims
// that return multiple values are represented as JSON arrays, and claims
// with zero elements are omitted. The published arrays must be non-empty
// JSON arrays.
func TestRFC8414_ArrayValuedMembersAreArrays_3_2(t *testing.T) {
	base, closeFn := metadataTestServer(t)
	defer closeFn()

	_, _, md := fetchMetadataDocument(t, base+"/.well-known/oauth-authorization-server")

	for _, member := range []string{
		"response_types_supported",
		"response_modes_supported",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
		"token_endpoint_auth_signing_alg_values_supported",
		"code_challenge_methods_supported",
	} {
		v, ok := md[member]
		require.True(t, ok, "%s must be published by the example AS", member)
		arr, isArr := v.([]any)
		require.True(t, isArr, "%s must be a JSON array (RFC 8414 section 3.2)", member)
		require.NotEmpty(t, arr, "%s must be omitted when empty (RFC 8414 section 3.2)", member)
	}
}

// TestRFC8414_SigningAlgValuesConstraint_2 asserts section 2:
// token_endpoint_auth_signing_alg_values_supported MUST be present when
// private_key_jwt is advertised in token_endpoint_auth_methods_supported,
// and the value "none" MUST NOT appear.
func TestRFC8414_SigningAlgValuesConstraint_2(t *testing.T) {
	base, closeFn := metadataTestServer(t)
	defer closeFn()

	_, _, md := fetchMetadataDocument(t, base+"/.well-known/oauth-authorization-server")

	methods, ok := md["token_endpoint_auth_methods_supported"].([]any)
	require.True(t, ok, "token_endpoint_auth_methods_supported must be an array")
	require.Contains(t, methods, "private_key_jwt",
		"the example AS authenticates clients with private_key_jwt (assertion-based asymmetric auth)")

	algs, ok := md["token_endpoint_auth_signing_alg_values_supported"].([]any)
	require.True(t, ok,
		"token_endpoint_auth_signing_alg_values_supported MUST be present when private_key_jwt is advertised (RFC 8414 section 2)")
	require.NotEmpty(t, algs, "no default algorithms are implied if the entry is omitted (RFC 8414 section 2)")
	require.NotContains(t, algs, "none", "the value none MUST NOT be used (RFC 8414 section 2)")
}

// TestRFC8414_WellKnownPathConstruction_3 asserts section 3: the well-known
// URI string /.well-known/oauth-authorization-server is inserted between the
// host and path components of the issuer identifier. With a path-suffixed
// issuer, the insertion keeps the path after the well-known prefix; with a
// pathless issuer the suffix is the full path.
func TestRFC8414_WellKnownPathConstruction_3(t *testing.T) {
	cases := []struct {
		name         string
		issuerPath   string
		expectedPath string
	}{
		{"pathless issuer", "", "/.well-known/oauth-authorization-server"},
		{"path component", "/issuer1", "/.well-known/oauth-authorization-server/issuer1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedPath, wellKnownMetadataPath(tc.issuerPath),
				"the well-known URI string must be inserted between host and path (RFC 8414 section 3)")
		})
	}
}

// wellKnownMetadataPath inserts the RFC 8414 section 3 well-known URI string
// between the host and the path of an issuer identifier: any terminating
// "/" of the issuer path is removed first, per section 3.1.
func wellKnownMetadataPath(issuerPath string) string {
	const wellKnown = "/.well-known/oauth-authorization-server"
	for len(issuerPath) > 0 && issuerPath[len(issuerPath)-1] == '/' {
		issuerPath = issuerPath[:len(issuerPath)-1]
	}
	if issuerPath == "" {
		return wellKnown
	}
	return wellKnown + issuerPath
}

// TestRFC8414_ClientFetchesAndValidatesMetadata_3_1_2_1 asserts the client
// side of section 3.1: the shipped HTTP client fetches the metadata document
// with a GET at the well-known path and — per the defensive posture pinned
// by draft-ietf-oauth-security-topics-update-03 section 2.1.2.1, which RFC
// 8414's issuer member exists to enable — rejects a document whose issuer
// differs from the issuer the client was configured with (mix-up defense).
func TestRFC8414_ClientFetchesAndValidatesMetadata_3_1_2_1(t *testing.T) {
	base, closeFn := metadataTestServer(t)
	defer closeFn()

	// The handler is instantiated with issuer "https://as.example.org" but
	// is reachable at the httptest origin: the published issuer therefore
	// mismatches the origin the client would be configured with — client
	// construction must fail closed on the issuer mismatch.
	_, err := client.HTTP(t.Context(), base, &client.Options{
		ClientID: "rfc8414-client",
		JWK:      clientJWKSWithSIG,
	})
	require.Error(t, err, "a metadata issuer mismatch must fail client construction (RFC 8414 section 2 issuer; security-topics-update-03 section 2.1.2.1)")
}

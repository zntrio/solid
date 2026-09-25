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

package client

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Adversarial coverage for the client building blocks against
// draft-ietf-oauth-security-topics-update-03 section 2.1: an attacker AS
// (or MITM metadata) publishing a hostile token_endpoint must not capture
// assertions minted for the honest AS, nor redirect the client's requests
// unvalidated.

// clientJWK is an ES256 P-256 signing key fixture (same key material as the
// integration fixtures).
const clientJWK = `{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`

// clientJWKS is the matching public JWKS document.
const clientJWKS = `{"keys": [{"kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`

// metadataServer serves an authorization server metadata document and a
// JWKS endpoint from a single origin. issuerValue may be empty to simulate
// a metadata document omitting the issuer field.
func metadataServer(t *testing.T, issuerValue, tokenEndpoint string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"token_endpoint":                        tokenEndpoint,
			"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
			"jwks_uri":                              srv.URL + "/keys",
		}
		if issuerValue != "" {
			doc["issuer"] = issuerValue
		}
		require.NoError(t, json.NewEncoder(w).Encode(doc))
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(clientJWKS))
		require.NoError(t, err)
	})
	return srv
}

// assertionAudClaim decodes the aud claim out of a signed assertion JWT.
func assertionAudClaim(t *testing.T, assertion string) any {
	t.Helper()

	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Contains(t, claims, "aud")
	return claims["aud"]
}

// TestHTTP_IssuerMismatchInServerMetadataRejected asserts the section 2.1.1
// attack at the client boundary: a server publishing metadata whose issuer
// differs from the issuer the client was configured to talk to (attacker AS
// or MITM metadata) fails client construction
// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1: clients MUST
// retrieve and validate the issuer identifier).
func TestHTTP_IssuerMismatchInServerMetadataRejected(t *testing.T) {
	// The server reached at its origin claims a different issuer in its
	// metadata document.
	srv := metadataServer(t, "https://attacker.example", "https://attacker.example/token")
	defer srv.Close()

	_, err := HTTP(t.Context(), srv.URL, &Options{
		ClientID: "test-client",
		JWK:      []byte(clientJWK),
	})
	require.Error(t, err, "a server metadata issuer mismatch must fail client construction")
	require.Contains(t, err.Error(), srv.URL)
}

// TestHTTP_AttackerTokenEndpointDoesNotHijackAssertionAudience asserts the
// section 2.1.1 core against the shipped client: when the (attacker)
// server's metadata omits the issuer value — construction is tolerated for
// honest older ASes — but publishes a token_endpoint pointing at the honest
// AS, the minted assertion's aud MUST still be the expected issuer passed
// to HTTP, never the discovered token_endpoint.
func TestHTTP_AttackerTokenEndpointDoesNotHijackAssertionAudience(t *testing.T) {
	honestASTokenEndpoint := "https://honest.example/token"

	// Attacker server: metadata without issuer, token_endpoint redirected
	// to the honest AS (the section 2.1.1 metadata attack).
	srv := metadataServer(t, "", honestASTokenEndpoint)
	defer srv.Close()

	c, err := HTTP(t.Context(), srv.URL, &Options{
		ClientID: "test-client",
		JWK:      []byte(clientJWK),
	})
	require.NoError(t, err, "construction with an issuer-less metadata document must be tolerated (older honest ASes omit it)")

	assertion, err := c.Assertion()
	require.NoError(t, err)

	aud := assertionAudClaim(t, assertion)
	require.Equal(t, srv.URL, aud,
		"the assertion aud must be the expected issuer identifier, never the discovered (possibly hijacked) token_endpoint")
}

// TestHTTP_HonestMetadataAssertionAudienceIsIssuerIdentifier asserts the
// positive path against an honest server: the metadata document carries the
// matching issuer and a token_endpoint that differs from it, and the minted
// assertion aud equals the issuer identifier passed to HTTP
// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1).
func TestHTTP_HonestMetadataAssertionAudienceIsIssuerIdentifier(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"token_endpoint":                        srv.URL + "/token",
			"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
			"jwks_uri":                              srv.URL + "/keys",
		}))
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(clientJWKS))
		require.NoError(t, err)
	})

	c, err := HTTP(t.Context(), srv.URL, &Options{
		ClientID: "test-client",
		JWK:      []byte(clientJWK),
	})
	require.NoError(t, err, "construction against an honest, matching metadata document must succeed")

	assertion, err := c.Assertion()
	require.NoError(t, err)

	aud := assertionAudClaim(t, assertion)
	require.Equal(t, srv.URL, aud,
		"the assertion aud must be the issuer identifier even when the discovered token_endpoint differs from it")
}

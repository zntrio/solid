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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/pkce"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/storage/inmemory"
)

// HTTP presentation-layer posture (checklist): CORS absence, no token
// values in error responses, cache-control no-store (RFC 6749 section
// 5.1), well-known metadata disclosure limits, and the authorization
// redirect URI exact-match rule (draft-ietf-oauth-v2-1-16 section 8.4 /
// server/services/redirect.go). The handlers under test are the real
// httpkit ones wired over the harness service stack — the same handlers
// examples/authorizationserver mounts.

// httpPostureTokenServer wires the real token handler (with the
// client-authentication middleware) over the harness stack, mirroring the
// example assembly.
func httpPostureTokenServer(t testing.TB, h *harness) *httptest.Server {
	proofs := inmemory.DPoPProofs()
	cleanupStores(t, proofs)
	return httptest.NewServer(httpkit.ClientAuthentication(
		h.clients,
		h.issuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		proofs,
		profile.Strict(),
	)(httpkit.Token(h.issuer, h.tokenz, buildDPoPVerifier(t), profile.Strict())))
}

// httpPostureAuthorizationServer wires the real authorization handler
// behind a basic-authentication middleware that injects the end-user
// subject (the login surface concern of the assembler). The hostile
// requests never reach the request-object decoder: they fail at redirect
// validation or PAR resolution first.
func httpPostureAuthorizationServer(h *harness) *httptest.Server {
	return httptest.NewServer(httpkit.BasicAuthentication(func(_, _ string) (string, *httpkit.AuthenticationEvent, bool) {
		return "user-1", nil, true
	})(httpkit.Authorization(h.issuer, h.authz, h.clients, nil, nil, nil, profile.Strict())))
}

// TestHTTPPosture_NoCORSAutogen asserts the CORS posture: the server must
// not emit any Access-Control-* header on the token endpoint — neither on
// OPTIONS preflight nor on actual requests — unless a deployer
// deliberately wires CORS. A future addition must be a conscious decision,
// and this pin moves with it.
func TestHTTPPosture_NoCORSAutogen(t *testing.T) {
	h := newHarness(t)
	ts := httpPostureTokenServer(t, h)
	defer ts.Close()

	for _, method := range []string{http.MethodOptions, http.MethodPost} {
		req, err := http.NewRequest(method, ts.URL, strings.NewReader("grant_type=authorization_code"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://attacker.example")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = res.Body.Close() })

		for name := range res.Header {
			if strings.HasPrefix(strings.ToLower(name), "access-control-") {
				t.Errorf("%s response carries %s: %q — the server must not add CORS headers (deployer decision, not autogen)", method, name, res.Header.Get(name))
			}
		}
	}
}

// TestHTTPPosture_NoTokenValueInResponses asserts RFC 6749 section 5.2: the
// token-endpoint error envelope never echoes the submitted token, code or
// verifier values — the error descriptions are static strings, so an
// attacker probing the endpoint learns nothing about the credential he
// submitted (beyond the error code itself).
func TestHTTPPosture_NoTokenValueInResponses(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeRefreshToken})
	ts := httpPostureTokenServer(t, h)
	defer ts.Close()

	const (
		secretRefreshToken = "super-secret-refresh-token-value-attacker-submitted"
		secretVerifier     = "super-secret-verifier-value-attacker-submitted"
	)

	// Refresh grant with an unknown token: invalid_grant, and the
	// response body must not carry the submitted token value.
	form := url.Values{}
	form.Set("grant_type", oidc.GrantTypeRefreshToken)
	form.Set("refresh_token", secretRefreshToken)
	form.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	form.Set("client_assertion", validClientAssertion(t, client.ClientId))

	res, err := http.PostForm(ts.URL, form)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	var body map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	require.NotEqual(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(bodyBytes), secretRefreshToken,
		"the error response must not echo the submitted refresh token")

	// Authorization code grant with a hostile verifier: invalid_grant, no
	// verifier echo.
	formCode := url.Values{}
	formCode.Set("grant_type", oidc.GrantTypeAuthorizationCode)
	formCode.Set("code", "unknown-code")
	formCode.Set("code_verifier", secretVerifier)
	formCode.Set("redirect_uri", testRedirectURI)
	formCode.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	formCode.Set("client_assertion", validClientAssertion(t, client.ClientId))
	formCode.Set("DPoP", mustDPoPProof(t, ts.URL))

	resCode, err := http.PostForm(ts.URL, formCode)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resCode.Body.Close() })

	var codeBody map[string]any
	require.NoError(t, json.NewDecoder(resCode.Body).Decode(&codeBody))
	require.NotEqual(t, http.StatusOK, resCode.StatusCode)

	codeBodyBytes, err := json.Marshal(codeBody)
	require.NoError(t, err)
	require.NotContains(t, string(codeBodyBytes), secretVerifier,
		"the error response must not echo the submitted code_verifier")
}

// TestHTTPPosture_CacheControlNoStore asserts RFC 6749 section 5.1: token
// responses carry Cache-Control: no-store (and the Pragma companion) —
// token responses must never be cacheable by intermediaries, on both the
// error and the success path.
func TestHTTPPosture_CacheControlNoStore(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials})
	ts := httpPostureTokenServer(t, h)
	defer ts.Close()

	// Error path (WithError).
	form := url.Values{}
	form.Set("grant_type", oidc.GrantTypeRefreshToken)
	form.Set("refresh_token", "unknown")
	form.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	form.Set("client_assertion", validClientAssertion(t, client.ClientId))

	res, err := http.PostForm(ts.URL, form)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, "no-store", res.Header.Get("Cache-Control"), "error responses are non-cacheable per RFC 6749 section 5.1")
	require.Equal(t, "no-cache", res.Header.Get("Pragma"))

	// Successful path (WithJSON): mint a client_credentials token.
	ccForm := url.Values{}
	ccForm.Set("grant_type", oidc.GrantTypeClientCredentials)
	ccForm.Set("scope", "openid")
	ccForm.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	ccForm.Set("client_assertion", validClientAssertion(t, client.ClientId))

	ccRes, err := http.PostForm(ts.URL, ccForm)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ccRes.Body.Close() })
	require.Equal(t, http.StatusOK, ccRes.StatusCode)
	require.Equal(t, "no-store", ccRes.Header.Get("Cache-Control"), "token responses are non-cacheable per RFC 6749 section 5.1")
	require.Equal(t, "no-cache", ccRes.Header.Get("Pragma"))
}

// TestHTTPPosture_WellKnownNoSecrets asserts the disclosure limit of the
// RFC 8414 metadata document: only public metadata members are exposed —
// no secrets, no private key material. (The REQUIRED members themselves
// are covered by rfc8414_metadata_test.go; this pins the negative.)
func TestHTTPPosture_WellKnownNoSecrets(t *testing.T) {
	base, closeFn := metadataTestServer(t)
	defer closeFn()

	_, _, body := fetchMetadataDocument(t, base+"/.well-known/oauth-authorization-server")
	raw, err := json.Marshal(body)
	require.NoError(t, err)

	for _, forbidden := range []string{
		"client_secret",
		"registration_access_token",
		"storage_key",
		"\"d\":",
		"\"kty\"",
		"\"x\":",
		"\"y\":",
	} {
		require.NotContains(t, string(raw), forbidden,
			"the well-known metadata must not disclose %q", forbidden)
	}
}

// TestHTTPPosture_RedirectNeverOpen asserts the authorization-endpoint
// redirect posture (draft-ietf-oauth-v2-1-16 section 8.4, exact-match +
// loopback-port exception in server/services/redirect.go): a hostile
// redirect_uri — path traversal, prefix bypass, subdomain confusion —
// never yields a 30x to the attacker URI; the request fails closed with a
// direct 400 (RFC 6749 section 4.1.2.1: an invalid redirect_uri MUST NOT
// redirect).
func TestHTTPPosture_RedirectNeverOpen(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})
	ts := httpPostureAuthorizationServer(h)
	defer ts.Close()

	_, challenge, err := pkce.CodeVerifier()
	require.NoError(t, err)

	for name, hostileURI := range map[string]string{
		"path traversal":      "https://client.example.org/cb/../evil",
		"subdomain confusion": "https://client.example.org.evil.com/cb",
		"prefix bypass":       "https://client.example.org/cb/extra",
		"attacker authority":  "https://attacker.example/cb",
		"scheme downgrade":    "http://client.example.org/cb",
		"fragment injection":  "https://client.example.org/cb#frag",
		"query injection":     "https://client.example.org/cb?next=/evil",
	} {
		t.Run(name, func(t *testing.T) {
			q := url.Values{}
			q.Set("response_type", oidc.ResponseTypeCode)
			q.Set("client_id", client.ClientId)
			q.Set("redirect_uri", hostileURI)
			q.Set("scope", "openid profile")
			q.Set("state", "af0ifjsldkjoijaoijoijaoidja3456789012")
			q.Set("nonce", "n-0S6_WzA2Mj")
			q.Set("code_challenge", challenge)
			q.Set("code_challenge_method", "S256")
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/authorize?"+q.Encode(), nil)
			require.NoError(t, err)
			// The basic-authentication middleware injects the
			// end-user subject (login surface).
			req.SetBasicAuth("user", "password")

			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = res.Body.Close() })

			// Fail closed: never a redirect to the attacker URI.
			location := res.Header.Get("Location")
			require.Empty(t, location,
				"an unregistered redirect_uri must not be redirected (RFC 6749 section 4.1.2.1)")
			require.Equal(t, http.StatusBadRequest, res.StatusCode,
				"an unregistered redirect_uri must be answered with a direct 400")
		})
	}
}

// mustDPoPProof mints a DPoP proof for the token endpoint URL; the proof
// value itself is irrelevant for the negative assertions here.
func mustDPoPProof(t *testing.T, endpoint string) string {
	t.Helper()

	proof, err := buildDPoPProver(t).Prove("POST", endpoint)
	require.NoError(t, err)
	return proof
}

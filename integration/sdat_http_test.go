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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/sdk/token/jwt"
	tokensd "zntr.io/solid/sdk/token/sd"
	verifiable "zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services/authorization"
	backchannel "zntr.io/solid/server/services/backchannel"
	"zntr.io/solid/server/services/device"
	"zntr.io/solid/server/services/token"
	inmemory "zntr.io/solid/server/storage/inmemory"
)

// newSDATHarness wires the full harness stack with a draft-forten
// selectively disclosable access-token generator (JWT kind, DPoP
// confirmation required per draft-forten section 6), mirroring
// newHarness.
func newSDATHarness(t *testing.T) *harness {
	t.Helper()

	storageKey := []byte("integration-storage-key-0123456789ab")

	// AS signing key for the SD access tokens.
	asPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	asPrivKey, err := jwxjwk.Import(asPriv)
	require.NoError(t, err)
	require.NoError(t, asPrivKey.Set(jwxjwk.KeyIDKey, "sdat-as-key"))

	// The draft-forten generator: disclosable email / name, DPoP
	// confirmation mandatory at mint time.
	sdatIssuer, err := sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{Signer: jwt.AccessTokenSigner("ES256", func(context.Context) (jwk.Key, error) {
		return asPrivKey, nil
	})}, sdtoken.WithRequiredConfirmation(), sdtoken.WithDecoyDigests(2))
	require.NoError(t, err)
	sdatAccessTokens := tokensd.AccessTokenWithSelectiveDisclosure(
		sdatIssuer,
		map[string]any{
			"email": "user@example.com",
			"name":  "Alice Doe",
		},
	)

	authorizationCodes := generator.DefaultAuthorizationCode()
	requestURIs := generator.DefaultRequestURI()

	clients := inmemory.Clients()
	tokens := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests(storageKey)
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)
	userCodeAttempts := inmemory.UserCodeAttempts()

	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-rt-mac-key"))

	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	tokenz := token.New(sdatAccessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources)
	backchannelz := backchannel.New(clients, backchannelSessions, generator.DefaultAuthReqID(),
		backchannel.HintResolverFunc(func(context.Context, *flowv1.BackchannelAuthenticationRequest) (string, error) { return "", nil }),
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}), []string{"ES256"})
	devicez := device.New(clients, deviceSessions, generator.DefaultDeviceCode(), generator.DefaultDeviceUserCode(), userCodeAttempts)
	clientAuth := clientauthentication.PrivateKeyJWT(clients, proofs, testIssuer, []string{"ES256"})

	return &harness{
		issuer:              testIssuer,
		clients:             clients,
		tokens:              tokens,
		resources:           resources,
		proofs:              proofs,
		authRequests:        authRequests,
		authSessions:        authSessions,
		deviceSessions:      deviceSessions,
		backchannelSessions: backchannelSessions,
		userCodeAttempts:    userCodeAttempts,
		authz:               authz,
		tokenz:              tokenz,
		devicez:             devicez,
		backchannelz:        backchannelz,
		clientAuth:          clientAuth,
	}
}

// sdatHTTPServer wires the real Token handler (client-authentication
// middleware + the shared DPoP verifier) over the SD harness.
func sdatHTTPServer(h *harness) *httptest.Server {
	return httptest.NewServer(httpkit.ClientAuthentication(
		h.clients,
		h.issuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		inmemory.DPoPProofs(),
		profile.Strict(),
	)(httpkit.Token(h.issuer, h.tokenz, buildDPoPVerifier(), profile.Strict())))
}

// sdatPostTokenRequest posts the authorization-code grant with a DPoP
// proof (draft-forten section 6: SD access tokens are DPoP-bound, so
// the mint carries cnf.jkt of the proof key).
func sdatPostTokenRequest(t *testing.T, ts *httptest.Server, form url.Values) (*http.Response, map[string]any) {
	t.Helper()

	// DPoP proof bound to the token endpoint (draft-forten section 6:
	// SD access tokens are DPoP-bound; the mint carries cnf.jkt of
	// the proof key). The proof htu must equal dpop.CleanURL(request):
	// both sides use the explicit /token path.
	endpoint := ts.URL + "/token"
	proof, err := buildDPoPProver(t).Prove("POST", endpoint)
	if err != nil {
		t.Fatalf("unable to mint dpop proof: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })

	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("unable to decode token response: %v", err)
	}
	return res, body
}

// TestSDATHTTPResponseCarriesDisclosures drives the real token endpoint
// with a draft-forten SD access-token generator behind it
// (draft-forten section 4): the token response JSON carries the
// `disclosures` parameter with exactly the issued disclosures; the
// access_token is an at+jwt JWT whose payload carries _sd / _sd_alg and
// NO cleartext email / name; the refresh grant mints fresh disclosures
// matching the refreshed token.
func TestSDATHTTPResponseCarriesDisclosures(t *testing.T) {
	h := newSDATHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	ts := sdatHTTPServer(h)
	defer ts.Close()

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	require.NotEmpty(t, code)

	form := url.Values{}
	form.Set("grant_type", oidc.GrantTypeAuthorizationCode)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	form.Set("client_assertion", validClientAssertion(t, client.ClientId))

	res, body := sdatPostTokenRequest(t, ts, form)
	require.Equal(t, http.StatusOK, res.StatusCode, "body = %v", body)

	// draft-forten section 4: the `disclosures` parameter carries the
	// issued disclosures.
	disclosuresRaw, has := body["disclosures"]
	require.True(t, has, "token response must carry the disclosures parameter")
	disclosures, ok := disclosuresRaw.([]any)
	require.True(t, ok, "disclosures must be a JSON array")
	require.Len(t, disclosures, 2, "email + name disclosures")

	// The access token: typ at+jwt, digests in, no cleartext values.
	accessToken, _ := body["access_token"].(string)
	require.NotEmpty(t, accessToken)
	require.False(t, strings.Contains(accessToken, "~"), "the token string must not carry the disclosures")
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3)

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	require.Equal(t, "at+jwt", header["typ"], "the token keeps its ordinary typ")

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadJSON, &payload))
	require.Contains(t, payload, "_sd")
	require.Equal(t, "sha-256", payload["_sd_alg"])
	require.NotContains(t, payload, "email", "the payload must not carry the email value")
	require.NotContains(t, payload, "name", "the payload must not carry the name value")

	// The disclosures decode as RFC 9901 JSON arrays carrying the user
	// claims, and the digests in the payload commit them.
	var emailFound, nameFound bool
	for _, d := range disclosures {
		dString, _ := d.(string)
		raw, errD := base64.RawURLEncoding.DecodeString(dString)
		require.NoError(t, errD)
		var arr []any
		require.NoError(t, json.Unmarshal(raw, &arr))
		require.Len(t, arr, 3)
		switch arr[1] {
		case "email":
			emailFound = true
			require.Equal(t, "user@example.com", arr[2])
		case "name":
			nameFound = true
			require.Equal(t, "Alice Doe", arr[2])
		}
	}
	require.True(t, emailFound && nameFound, "email and name disclosures must both be present")

	// Refresh: the grant re-mints the SD access token; fresh
	// disclosures ride the refreshed response (fresh salts, digests
	// matching the new token).
	refreshToken, _ := body["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", oidc.GrantTypeRefreshToken)
	refreshForm.Set("refresh_token", refreshToken)
	refreshForm.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	refreshForm.Set("client_assertion", validClientAssertion(t, client.ClientId))

	refreshRes, refreshBody := sdatPostTokenRequest(t, ts, refreshForm)
	require.Equal(t, http.StatusOK, refreshRes.StatusCode, "refresh body = %v", refreshBody)

	refreshedDisclosures, has := refreshBody["disclosures"].([]any)
	require.True(t, has, "the refreshed response must carry fresh disclosures")
	require.Len(t, refreshedDisclosures, 2)

	refreshedToken, _ := refreshBody["access_token"].(string)
	require.NotEmpty(t, refreshedToken)
	require.NotEqual(t, accessToken, refreshedToken, "the refreshed access token is a fresh mint")

	// The refreshed token's payload commits the refreshed disclosures:
	// every refreshed disclosure digest appears in its _sd array.
	refreshedParts := strings.Split(refreshedToken, ".")
	refreshedPayloadJSON, err := base64.RawURLEncoding.DecodeString(refreshedParts[1])
	require.NoError(t, err)
	var refreshedPayloadMap map[string]any
	require.NoError(t, json.Unmarshal(refreshedPayloadJSON, &refreshedPayloadMap))
	sdAny, hasSD := refreshedPayloadMap["_sd"].([]any)
	require.True(t, hasSD)
	sdSet := map[string]bool{}
	for _, d := range sdAny {
		if s, isString := d.(string); isString {
			sdSet[s] = true
		}
	}
	for _, d := range refreshedDisclosures {
		dString, _ := d.(string)
		digest := sha256Base64(dString)
		require.True(t, sdSet[digest], "the refreshed disclosure digest must be committed in the refreshed token")
	}
}

// TestSDATHTTPIntrospectionNoDisclosures asserts the introspection
// response of an SD access token carries no `disclosures` member (the
// strings carry the actual values — they MUST NOT leak;
// draft-forten section 5.3: the introspection response carries no
// Disclosure).
func TestSDATHTTPIntrospectionNoDisclosures(t *testing.T) {
	h := newSDATHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	// The DPoP key confirmation of the shared fixture key (the jkt the
	// mint requires under WithRequiredConfirmation).
	dpopKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	tp, err := dpopKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	jkt := base64.RawURLEncoding.EncodeToString(tp)

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	grantReq := codeGrantRequest(h.issuer, client.ClientId, code, verifier, testRedirectURI)
	grantReq.TokenConfirmation = &tokenv1.TokenConfirmation{Jkt: jkt}
	res, err := h.tokenz.Token(context.Background(), grantReq)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Disclosures, "the persisted token spec carries the disclosures")

	// The real introspection handler over the harness introspection
	// path, with the stored SD token spec injected.
	fake := &sdatIntrospectToken{token: res.AccessToken}
	inner := httpkit.TokenIntrospection("https://as.example.org", fake)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(clientauthentication.Inject(r.Context(), &clientv1.Client{ClientId: client.ClientId}))
		inner.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := srv.Client().PostForm(srv.URL, url.Values{"token": {res.AccessToken.Value}})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.NotContains(t, body, "disclosures", "introspection response MUST NOT carry the disclosures")
	require.Equal(t, true, body["active"])
}

// sdatIntrospectToken is a minimal services.Token resolving the stored
// SD token spec (the real service resolves from storage; the shape is
// identical).
type sdatIntrospectToken struct {
	token *tokenv1.Token
}

func (f *sdatIntrospectToken) Token(context.Context, *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	return nil, nil
}

func (f *sdatIntrospectToken) Revoke(context.Context, *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	return nil, nil
}

// Introspect resolves the stored SD token spec: the response the
// handler maps never includes the disclosures member (the explicit
// member set is iss, aud, iat, exp, client_id, scope, sub, jti, cnf,
// authorization_details — the spec's Disclosures stay server-side).
func (f *sdatIntrospectToken) Introspect(context.Context, *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	return &tokenv1.IntrospectResponse{
		Token: &tokenv1.Token{
			TokenId: f.token.TokenId,
			Status:  f.token.Status,
			Metadata: &tokenv1.TokenMeta{
				Issuer:               "https://as.example.org",
				Subject:              f.token.Metadata.Subject,
				ClientId:             f.token.Metadata.ClientId,
				Audience:             "aud",
				NotBefore:            1,
				ExpiresAt:            4102444800,
				AuthorizationDetails: f.token.Metadata.AuthorizationDetails,
			},
			Disclosures: f.token.Disclosures,
		},
	}, nil
}

// sha256Base64 computes the RFC 9901 digest key of a disclosure wire
// string: base64url(sha256(ASCII(wire))).
func sha256Base64(wire string) string {
	sum := sha256.Sum256([]byte(wire))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

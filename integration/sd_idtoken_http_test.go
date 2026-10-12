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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/pairwise"
	random "zntr.io/solid/sdk/random"
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

// newSDIDTokenHarness wires the full harness stack with a D-12.1 opt-in
// SD-JWT ID-token generator (id+jwt, IDTokenProfile), mirroring
// newSDATHarness. The AS access/refresh generators are plain mocks of
// the stack shape; the focus is the id_token mint.
func newSDIDTokenHarness(t *testing.T) (*sdidtHarness, jwk.Set) {
	t.Helper()

	storageKey := []byte("integration-storage-key-0123456789ab")

	// AS signing key for the SD ID token.
	asPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	asPrivKey, err := jwxjwk.Import(asPriv)
	require.NoError(t, err)
	require.NoError(t, asPrivKey.Set(jwxjwk.KeyIDKey, "sdidt-as-key"))

	// D-12.1 generator: SD ID tokens per the IDTokenProfile — iss, sub,
	// aud, exp, iat, jti, nonce, auth_time, acr protected; email / name
	// disclosable.
	idIssuer, err := sdjwt.NewAccessTokenIssuer(sdtoken.IDTokenProfile, sdjwt.Deps{
		Signer: jwt.RawTypedSigner("id+jwt", "ES256", func(context.Context) (jwk.Key, error) {
			return asPrivKey, nil
		}),
	}, sdtoken.WithDecoyDigests(2))
	require.NoError(t, err)
	idTokens := tokensd.IDTokenWithSelectiveDisclosure(
		idIssuer,
		nil, // no extra protected claims
		map[string]any{
			"email": "alice@example.org",
			"name":  "Alice Doe",
		},
	)

	// AS key set for verification in the test.
	asPub, err := asPrivKey.PublicKey()
	require.NoError(t, err)
	asPubSet := jwxjwk.NewSet()
	require.NoError(t, asPubSet.AddKey(asPub))

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

	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-at-mac-key"))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-rt-mac-key"))

	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	tokenz := token.NewWithOptions(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources, token.WithIDTokenGenerator(idTokens))
	backchannelz := backchannel.New(clients, backchannelSessions, generator.DefaultAuthReqID(),
		backchannel.HintResolverFunc(func(context.Context, *flowv1.BackchannelAuthenticationRequest) (string, error) { return "", nil }),
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}), []string{"ES256"})
	devicez := device.New(clients, deviceSessions, generator.DefaultDeviceCode(), generator.DefaultDeviceUserCode(), userCodeAttempts, authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	clientAuth := clientauthentication.PrivateKeyJWT(clients, proofs, testIssuer, []string{"ES256"})
	h := &sdidtHarness{
		harness: &harness{
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
		},
		signingKey: asPrivKey,
		verifySet:  asPubSet,
	}
	return h, asPubSet
}

// sdidtHarness binds the local SD ID-token test state (AS signing key
// for JARM + id_token verification) to the shared harness.
type sdidtHarness struct {
	*harness
	signingKey jwk.Key
	verifySet  jwk.Set
}

// seedAuthorizationPairwise drives the REAL /authorize HTTP handler over
// the harness (Basic-authenticated resource owner standing in for the
// user agent): the handler applies the pairwise encoding before issuing
// the code, exactly as the reference assembly does. Returns the code
// and the pairwise subject the session carries.
func (h *sdidtHarness) seedAuthorizationPairwise(t *testing.T, client *clientv1.Client, verifier, redirectURI string) (string, string) {
	t.Helper()

	// Assemble the authorization request the way PAR does in the other
	// harnesses, then register it.
	req := validAuthorizationRequest(client.ClientId, verifier, redirectURI)
	requestURI := "urn:solid:" + random.String(32)
	ctx := context.Background()
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}

	// Real /authorize handler: security headers + Basic login + JARM
	// (the strict profile requires a JWT response mode — the registered
	// request carries response_mode=jwt).
	jarmEncoder := jarm.Encoder(jwt.JARMSigner("ES256", func(context.Context) (jwk.Key, error) {
		return h.signingKey, nil
	}))
	authHandler := httpkit.Authorization(
		h.issuer,
		h.authz,
		h.clients,
		jarmEncoder,
		pairwise.Hash([]byte("sdidt-integration-salt-0123456789")),
		nil, // requestObjectAlgorithms
		profile.Strict(),
	)
	srv := httptest.NewServer(httpkit.Adapt(authHandler, httpkit.SecurityHeaders(), httpkit.BasicAuthentication(func(u, p string) (string, *httpkit.AuthenticationEvent, bool) {
		if u == "hello" && p == "world" {
			return u, &httpkit.AuthenticationEvent{
				ACR:      "urn:solid:loa:1fa:any",
				AuthTime: uint64(time.Now().Unix()), //nolint:gosec // unix time is non-negative
			}, true
		}
		return "", nil, false
	})))
	t.Cleanup(srv.Close)

	// Do not follow the redirect: the JARM response is the Location
	// header itself (client.example.org is not resolvable here).
	srv.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Drive it with the request_uri.
	endpoint := srv.URL + "/authorize?response_type=code&client_id=" + url.QueryEscape(client.ClientId) + "&request_uri=" + url.QueryEscape(requestURI)
	httpReq, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpReq.SetBasicAuth("hello", "world")
	httpRes, err := srv.Client().Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = httpRes.Body.Close() }()

	// The JARM response travels as the `response` query parameter of the
	// redirect; decode it with the shared verifier to extract the code.
	require.Equal(t, http.StatusFound, httpRes.StatusCode)
	loc, err := url.Parse(httpRes.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	responseParam := loc.Query().Get("response")
	require.NotEmpty(t, responseParam, "Location = %s", httpRes.Header.Get("Location"))
	decoded, err := jarm.Decoder(h.issuer, jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return h.verifySet, nil }, []string{"ES256"})).Decode(context.Background(), client.ClientId, responseParam)
	if err != nil {
		t.Fatal(err)
	}
	require.NotNil(t, decoded)
	code := decoded.Code
	require.NotEmpty(t, code)

	// The pairwise subject the handler minted: same salt, sector =
	// the client's SectorIdentifier (falling back to the client_id as
	// the handler does), subject = the Basic-login user.
	sector := client.SectorIdentifier
	if sector == "" {
		sector = client.ClientId
	}
	pairwiseSub, err := pairwise.Hash([]byte("sdidt-integration-salt-0123456789")).Encode(sector, "hello")
	if err != nil {
		t.Fatal(err)
	}
	return code, pairwiseSub
}

// sdidtHTTPServer wires the real Token handler (client-authentication
// middleware + the shared DPoP verifier) over the SD ID-token harness.
func sdidtHTTPServer(h *harness) *sdidtServer {
	ts := httptest.NewServer(httpkit.ClientAuthentication(
		h.clients,
		h.issuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		inmemory.DPoPProofs(),
		profile.Strict(),
	)(httpkit.Token(h.issuer, h.tokenz, buildDPoPVerifier(), profile.Strict())))
	return &sdidtServer{ts: ts}
}

type sdidtServer struct{ ts *httptest.Server }

func (s *sdidtServer) url() string { return s.ts.URL + "/token" }
func (s *sdidtServer) close()      { s.ts.Close() }

// post redeems the form at the token endpoint with a DPoP proof (the
// strict profile requires DPoP at the token endpoint).
func (s *sdidtServer) post(t *testing.T, form url.Values) (*http.Response, map[string]any) {
	t.Helper()

	endpoint := s.url()
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

// redeemCode drives the authorization-code grant for the given client
// through the real /authorize + /token HTTP handlers, returning the
// response body and the pairwise subject minted at authorization.
func redeemCode(t *testing.T, h *sdidtHarness, s *sdidtServer, client *clientv1.Client) (*http.Response, map[string]any, string) {
	t.Helper()

	verifier, _ := newPKCEPair(t)
	code, pairwiseSub := h.seedAuthorizationPairwise(t, client, verifier, testRedirectURI)
	require.NotEmpty(t, code)

	form := url.Values{}
	form.Set("grant_type", oidc.GrantTypeAuthorizationCode)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	form.Set("client_assertion", validClientAssertion(t, client.ClientId))

	res, body := s.post(t, form)
	return res, body, pairwiseSub
}

// TestSDIDTokenHTTPResponse drives the real token endpoint with a
// D-12.1 opt-in SD ID-token generator behind it: the response carries
// id_token + id_token_disclosures; the id_token is an id+jwt JWT whose
// payload carries _sd / _sd_alg and NO cleartext email / name; nonce,
// pairwise sub, aud = client_id; each disclosure digest is committed
// in the payload _sd array. The default-off posture (no option wired)
// is pinned by the negative subtest.
func TestSDIDTokenHTTPResponse(t *testing.T) {
	h, asPubSet := newSDIDTokenHarness(t)
	client := h.registerPairwiseClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	s := sdidtHTTPServer(h.harness)
	defer s.close()

	res, body, pairwiseSub := redeemCode(t, h, s, client)
	require.Equal(t, http.StatusOK, res.StatusCode, "body = %v", body)

	// id_token present: 3-segment compact JWT.
	idToken, has := body["id_token"].(string)
	require.True(t, has, "token response must carry id_token")
	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3)

	// id_token_disclosures: exactly email + name.
	disclosuresRaw, has := body["id_token_disclosures"]
	require.True(t, has, "token response must carry id_token_disclosures")
	disclosures, ok := disclosuresRaw.([]any)
	require.True(t, ok, "id_token_disclosures must be a JSON array")
	require.Len(t, disclosures, 2, "email + name disclosures")

	// Header: typ id+jwt, alg ES256.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	require.Equal(t, "id+jwt", header["typ"])
	require.Equal(t, "ES256", header["alg"])

	// Signature verifies against the AS public key set.
	idVerifier := jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return asPubSet, nil }, []string{"ES256"})
	require.NoError(t, idVerifier.Verify(idToken))

	// Payload claims.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadJSON, &payload))
	require.Contains(t, payload, "_sd")
	require.Equal(t, "sha-256", payload["_sd_alg"])
	require.NotContains(t, payload, "email", "the id_token must not carry the email value")
	require.NotContains(t, payload, "name", "the id_token must not carry the name value")
	require.Equal(t, testIssuer, payload["iss"])
	require.Equal(t, client.ClientId, payload["aud"], "OIDC Core section 2: id_token aud is the client_id")
	require.Equal(t, "n-0S6_WzA2Mj", payload["nonce"], "the id_token echoes the request nonce")
	// The subject is the pairwise identifier the /authorize handler
	// minted for this client's sector — never the bare login subject.
	require.Equal(t, pairwiseSub, payload["sub"], "sub is the pairwise subject captured at authorization")
	require.NotEqual(t, "hello", payload["sub"], "the bare login subject must never appear")

	// Digest-binding: each disclosure decodes as an RFC 9901 JSON array
	// carrying a user claim, and its digest is committed in _sd.
	sdAny, hasSD := payload["_sd"].([]any)
	require.True(t, hasSD, "payload must carry _sd")
	sdSet := map[string]bool{}
	for _, d := range sdAny {
		if v, isString := d.(string); isString {
			sdSet[v] = true
		}
	}
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
			require.Equal(t, "alice@example.org", arr[2])
		case "name":
			nameFound = true
			require.Equal(t, "Alice Doe", arr[2])
		}
		require.True(t, sdSet[sha256Base64(dString)], "the disclosure digest must be committed in _sd")
	}
	require.True(t, emailFound && nameFound, "email and name disclosures must both be present")
}

// registerPairwiseClient registers a confidential pairwise-subject
// client (SubjectType pairwise + a sector identifier, mirroring the
// reference-assembly fixtures): the /authorize handler then applies the
// pairwise encoding before issuing the code.
func (h *sdidtHarness) registerPairwiseClient(t *testing.T, redirectURIs, grantTypes []string) *clientv1.Client {
	t.Helper()

	c := &clientv1.Client{
		ClientName:              "sdidt-pairwise-test-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		ResponseModes:           []string{oidc.ResponseModeQueryJWT},
		RedirectUris:            redirectURIs,
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		Jwks:                    clientJWKSWithSIG,
		SubjectType:             oidc.SubjectTypePairwise,
		SectorIdentifier:        "sdidt-sector",
	}

	if _, err := h.clients.Register(context.Background(), c); err != nil {
		t.Fatalf("unable to register client: %v", err)
	}
	return c
}

// TestSDIDTokenDefaultOff pins the default posture (D-12.1): a harness
// WITHOUT the ID-token generator wired issues no id_token — the
// redemption succeeds with access/refresh tokens only.
func TestSDIDTokenDefaultOff(t *testing.T) {
	h, _ := newSDIDTokenHarnessDefaultOff(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	s := sdidtHTTPServer(h.harness)
	defer s.close()

	res, body, _ := redeemCode(t, h, s, client)
	require.Equal(t, http.StatusOK, res.StatusCode, "body = %v", body)
	require.NotContains(t, body, "id_token", "default posture: no id_token in the response")
	require.NotContains(t, body, "id_token_disclosures", "default posture: no id_token_disclosures in the response")
}

// newSDIDTokenHarnessDefaultOff mirrors newSDIDTokenHarness without the
// WithIDTokenGenerator option (default posture).
func newSDIDTokenHarnessDefaultOff(t *testing.T) (*sdidtHarness, jwk.Set) {
	t.Helper()

	h, asPubSet := newSDIDTokenHarness(t)
	// Re-wire the token service without the ID-token generator.
	storageKey := []byte("integration-storage-key-0123456789ab")
	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-at-mac-key"))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-rt-mac-key"))
	tokenz := token.New(accessTokens, refreshTokens, h.clients, h.authSessions, h.deviceSessions, h.backchannelSessions, inmemory.Tokens(storageKey), h.resources)
	h.tokenz = tokenz
	return h, asPubSet
}

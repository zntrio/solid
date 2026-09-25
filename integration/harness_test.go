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

// Package integration hosts adversarial tests derived from RFC 9700 (OAuth
// 2.0 Security Best Current Practice). Each test plays one of the RFC's
// attacker roles (A1 web attacker, A2 network attacker, A3 authorization code
// attacker, A4 request observer, A5 token attacker) against the real service
// stack wired with in-memory storage, and asserts the corresponding
// countermeasure fires.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/jwsreq"
	"zntr.io/solid/sdk/pkce"
	"zntr.io/solid/sdk/random"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/device"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------

const (
	testIssuer        = "http://127.0.0.1:8080"
	testTokenEndpoint = testIssuer + "/token"
	testRedirectURI   = "https://client.example.org/cb"
)

// clientPrivateKey / clientJWKSWithSIG are ES256 P-256 fixtures shared with
// server/clientauthentication tests.
var (
	clientPrivateKey  = []byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)
	clientJWKSWithSIG = []byte(`{"keys": [{"kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`)
)

// -----------------------------------------------------------------------------

// harness wires the real authorization and token services with in-memory
// storage, mirroring examples/authorizationserver/main.go.
type harness struct {
	issuer           string
	clients          storage.Client
	tokens           storage.Token
	resources        storage.ResourceReader
	proofs           storage.DPoP
	authRequests     storage.AuthorizationRequest
	authSessions     storage.AuthorizationCodeSession
	deviceSessions   storage.DeviceCodeSession
	userCodeAttempts storage.UserCodeAttempts
	authz            services.Authorization
	tokenz           services.Token
	devicez          services.Device
	clientAuth       clientauthentication.AuthenticationProcessor
}

// newHarness builds a fully wired service stack.
func newHarness(t *testing.T) *harness {
	t.Helper()

	storageKey := []byte("integration-storage-key-0123456789ab")

	// Generators
	authorizationCodes := generator.DefaultAuthorizationCode()
	requestURIs := generator.DefaultRequestURI()

	// Storage
	clients := inmemory.Clients()
	tokens := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests(storageKey)
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	userCodeAttempts := inmemory.UserCodeAttempts()

	// Token generators
	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-at-mac-key"))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-rt-mac-key"))

	// Services
	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	tokenz := token.New(accessTokens, refreshTokens, clients, authRequests, authSessions, deviceSessions, tokens, resources)
	devicez := device.New(clients, deviceSessions, generator.DefaultDeviceCode(), generator.DefaultDeviceUserCode(), userCodeAttempts)
	clientAuth := clientauthentication.PrivateKeyJWT(clients, proofs, testIssuer, []string{"ES256"})

	return &harness{
		issuer:           testIssuer,
		clients:          clients,
		tokens:           tokens,
		resources:        resources,
		proofs:           proofs,
		authRequests:     authRequests,
		authSessions:     authSessions,
		deviceSessions:   deviceSessions,
		userCodeAttempts: userCodeAttempts,
		authz:            authz,
		tokenz:           tokenz,
		devicez:          devicez,
		clientAuth:       clientAuth,
	}
}

// registerConfidentialClient registers a confidential client with the given
// redirect URIs and grant types, sharing the ES256 signing JWKS fixture.
func (h *harness) registerConfidentialClient(t *testing.T, redirectURIs, grantTypes []string) *clientv1.Client {
	t.Helper()

	c := &clientv1.Client{
		ClientName:              "adversarial-test-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		RedirectUris:            redirectURIs,
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		Jwks:                    clientJWKSWithSIG,
	}

	if _, err := h.clients.Register(context.Background(), c); err != nil {
		t.Fatalf("unable to register client: %v", err)
	}
	return c
}

// registerDeviceDPoPClient registers a confidential client restricted to the
// device_code grant whose access tokens must be DPoP-bound (RFC 10027
// section 6.1.12 sender-constrained tokens).
func (h *harness) registerDeviceDPoPClient(t *testing.T) *clientv1.Client {
	t.Helper()

	c := &clientv1.Client{
		ClientName:              "dpop-device-test-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{oidc.GrantTypeDeviceCode},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		Jwks:                    clientJWKSWithSIG,
		DpopBoundAccessTokens:   true,
	}

	if _, err := h.clients.Register(context.Background(), c); err != nil {
		t.Fatalf("unable to register DPoP device client: %v", err)
	}
	return c
}

// validAuthorizationRequest assembles an AuthorizationRequest satisfying every
// mandatory field of authorization.validate, using S256(verifier) as challenge.
func validAuthorizationRequest(clientID, verifier, redirectURI string) *flowv1.AuthorizationRequest {
	return &flowv1.AuthorizationRequest{
		Scope:               "openid offline_access profile",
		ResponseType:        oidc.ResponseTypeCode,
		ClientId:            clientID,
		RedirectUri:         redirectURI,
		State:               "af0ifjsldkjoijaoijoijaoidja3456789012",
		Nonce:               "n-0S6_WzA2Mj",
		Prompt:              new(oidc.PromptConsent),
		Audience:            "urn:example:cooperation-context",
		CodeChallenge:       s256Challenge(verifier),
		CodeChallengeMethod: oidc.CodeChallengeMethodSha256,
	}
}

// s256Challenge computes the RFC 7636 S256 code challenge of a verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// seedAuthorization registers the request through the PAR-style endpoint then
// drives the real Authorize flow, returning the emitted authorization code.
func (h *harness) seedAuthorization(t *testing.T, client *clientv1.Client, req *flowv1.AuthorizationRequest) string {
	t.Helper()

	ctx := context.Background()

	// Register the authorization request (PAR-style) with a well-formed
	// request_uri, as produced by generator.DefaultRequestURI.
	requestURI := "urn:solid:" + random.String(32)
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}
	req.RequestUri = new(string)
	*req.RequestUri = requestURI

	// Authorize
	res, err := h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	if err != nil {
		t.Fatalf("unable to authorize: %v", err)
	}
	if res.Error != nil {
		t.Fatalf("authorization failed: %s", res.Error.Err)
	}
	if res.Code == "" {
		t.Fatal("authorization response has no code")
	}
	return res.Code
}

// authenticate runs the private_key_jwt client authentication at the given
// receiving endpoint (draft-ietf-oauth-security-topics-update-03 section
// 2.1.2.2: the assertion audience must match the endpoint that actually
// received it, or the AS issuer identifier).
func (h *harness) authenticate(t *testing.T, endpoint, assertion string) (*clientv1.AuthenticateResponse, error) {
	t.Helper()

	assertionType := oidc.AssertionTypeJWTBearer
	return h.clientAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
		ClientAssertionType: &assertionType,
		ClientAssertion:     &assertion,
		Endpoint:            &endpoint,
	})
}

// codeGrantRequest builds a TokenRequest for the authorization_code grant.
func codeGrantRequest(issuer, clientID, code, verifier, redirectURI string) *flowv1.TokenRequest {
	return &flowv1.TokenRequest{
		Issuer:    issuer,
		GrantType: oidc.GrantTypeAuthorizationCode,
		Client:    &clientv1.Client{ClientId: clientID},
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{
				Code:         code,
				CodeVerifier: verifier,
				RedirectUri:  redirectURI,
			},
		},
	}
}

// refreshGrantRequest builds a TokenRequest for the refresh_token grant.
func refreshGrantRequest(issuer, clientID, refreshToken string) *flowv1.TokenRequest {
	return &flowv1.TokenRequest{
		Issuer:    issuer,
		GrantType: oidc.GrantTypeRefreshToken,
		Client:    &clientv1.Client{ClientId: clientID},
		Grant: &flowv1.TokenRequest_RefreshToken{
			RefreshToken: &flowv1.GrantRefreshToken{
				RefreshToken: refreshToken,
			},
		},
	}
}

// -----------------------------------------------------------------------------

// privateJWTClaims mirrors server/clientauthentication.privateJWTClaims.
type privateJWTClaims struct {
	JTI       string `json:"jti"`
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Expires   uint64 `json:"exp"`
	IssuedAt  uint64 `json:"iat"`
	NotBefore uint64 `json:"nbf,omitempty"`
}

// generateClientAssertion signs a private_key_jwt client assertion with the
// shared ES256 fixture key.
func generateClientAssertion(t *testing.T, claims *privateJWTClaims) string {
	t.Helper()

	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("unable to decode client private key: %v", err)
	}

	var rawKey any
	if err := jwxjwk.Export(privateKey, &rawKey); err != nil {
		t.Fatalf("unable to materialize client private key: %v", err)
	}

	claimsMap := gojwt.MapClaims{
		"jti": claims.JTI,
		"sub": claims.Subject,
		"iss": claims.Issuer,
		"aud": claims.Audience,
		"exp": claims.Expires,
		"iat": claims.IssuedAt,
	}
	if claims.NotBefore > 0 {
		claimsMap["nbf"] = claims.NotBefore
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, claimsMap)
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to serialize assertion: %v", err)
	}
	return raw
}

// validClientAssertion mints a well-formed assertion for the given client id,
// with aud bound to the AS issuer identifier
// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1).
func validClientAssertion(t *testing.T, clientID string) string {
	t.Helper()

	now := uint64(time.Now().Unix())
	return generateClientAssertion(t, &privateJWTClaims{
		JTI:       random.String(16),
		Subject:   clientID,
		Issuer:    clientID,
		Audience:  testIssuer,
		Expires:   now + 300,
		IssuedAt:  now,
		NotBefore: now,
	})
}

// authenticateClient resolves a full client through private_key_jwt auth.
func (h *harness) authenticateClient(t *testing.T, clientID string) *clientv1.Client {
	t.Helper()

	res, err := h.authenticate(t, testTokenEndpoint, validClientAssertion(t, clientID))
	require.NoError(t, err, "client authentication must succeed with valid assertion")
	require.NotNil(t, res, "authentication response must not be nil")
	require.NotNil(t, res.Client, "authenticated client must not be nil")
	return res.Client
}

// redeemCode authenticates the client then redeems the code at the token
// service, returning the token response.
func (h *harness) redeemCode(t *testing.T, clientID, code, verifier, redirectURI string) (*flowv1.TokenResponse, error) {
	t.Helper()

	h.authenticateClient(t, clientID)
	return h.tokenz.Token(context.Background(), codeGrantRequest(h.issuer, clientID, code, verifier, redirectURI))
}

// refresh authenticates the client then exercises the refresh grant.
func (h *harness) refresh(t *testing.T, clientID, refreshToken string) (*flowv1.TokenResponse, error) {
	t.Helper()

	h.authenticateClient(t, clientID)
	return h.tokenz.Token(context.Background(), refreshGrantRequest(h.issuer, clientID, refreshToken))
}

// newPKCEPair returns a fresh verifier and its S256 challenge.
func newPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()

	v, c, err := pkce.CodeVerifier()
	if err != nil {
		t.Fatalf("unable to generate PKCE verifier: %v", err)
	}
	return v, c
}

func buildDPoPProver(t *testing.T) dpop.Prover {
	t.Helper()

	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("unable to decode DPoP private key: %v", err)
	}
	if err := privateKey.Set(jwxjwk.KeyIDKey, "integration-dpop-key"); err != nil {
		t.Fatalf("unable to set DPoP key id: %v", err)
	}

	return dpop.DefaultProver(jwt.DPoPSigner("ES256", func(_ context.Context) (jwk.Key, error) {
		return privateKey, nil
	}))
}

func buildDPoPVerifier() dpop.Verifier {
	keySet, err := jwk.Parse(clientJWKSWithSIG)
	if err != nil {
		panic(err)
	}

	return dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.DefaultVerifier(func(_ context.Context) (jwk.Set, error) {
		return keySet, nil
	}, []string{"ES256"}))
}

// -----------------------------------------------------------------------------

// startDeviceAuthorization drives the device authorization service and returns
// the device_code / user_code pair (RFC 8628 section 3.2).
func (h *harness) startDeviceAuthorization(t *testing.T, client *clientv1.Client, scopes []string) (deviceCode, userCode string) {
	t.Helper()

	scope := strings.Join(scopes, " ")
	res, err := h.devicez.Authorize(context.Background(), &flowv1.DeviceAuthorizationRequest{
		Issuer:   h.issuer,
		ClientId: client.ClientId,
		Scope:    &scope,
	})
	if err != nil {
		t.Fatalf("unable to start device authorization: %v", err)
	}
	if res.Error != nil {
		t.Fatalf("device authorization failed: %s", res.Error.Err)
	}
	return res.DeviceCode, res.UserCode
}

// approveDevice validates the user code, completing the end-user interaction
// step of the device flow (RFC 8628 section 3.3).
func (h *harness) approveDevice(t *testing.T, userCode, subject string) {
	t.Helper()

	res, err := h.devicez.Validate(context.Background(), &flowv1.DeviceCodeValidationRequest{
		Issuer:   h.issuer,
		UserCode: userCode,
		Subject:  subject,
	})
	if err != nil {
		t.Fatalf("unable to approve device authorization: %v", err)
	}
	if res.Error != nil {
		t.Fatalf("device approval failed: %s", res.Error.Err)
	}
}

// deviceTokenRequest builds a TokenRequest for the device_code grant.
func deviceTokenRequest(issuer, clientID, deviceCode string) *flowv1.TokenRequest {
	return &flowv1.TokenRequest{
		Issuer:    issuer,
		GrantType: oidc.GrantTypeDeviceCode,
		Client:    &clientv1.Client{ClientId: clientID},
		Grant: &flowv1.TokenRequest_DeviceCode{
			DeviceCode: &flowv1.GrantDeviceCode{
				DeviceCode: deviceCode,
				ClientId:   clientID,
			},
		},
	}
}

// pollDeviceToken authenticates the client then polls the token endpoint with
// the device_code grant.
func (h *harness) pollDeviceToken(t *testing.T, clientID, deviceCode string) (*flowv1.TokenResponse, error) {
	t.Helper()

	h.authenticateClient(t, clientID)
	return h.tokenz.Token(context.Background(), deviceTokenRequest(h.issuer, clientID, deviceCode))
}

// pollDeviceTokenWithConfirmation polls the device_code grant carrying an
// explicit token confirmation (DPoP proof thumbprint).
func (h *harness) pollDeviceTokenWithConfirmation(t *testing.T, clientID, deviceCode string, cnf *tokenv1.TokenConfirmation) (*flowv1.TokenResponse, error) {
	t.Helper()

	req := deviceTokenRequest(h.issuer, clientID, deviceCode)
	req.TokenConfirmation = cnf
	h.authenticateClient(t, clientID)
	return h.tokenz.Token(context.Background(), req)
}

// revoke authenticates the client then exercises the revocation endpoint.
func (h *harness) revoke(t *testing.T, clientID, tokenValue string) (*tokenv1.RevokeResponse, error) {
	t.Helper()

	h.authenticateClient(t, clientID)
	return h.tokenz.Revoke(context.Background(), &tokenv1.RevokeRequest{
		Issuer: h.issuer,
		Client: &clientv1.Client{ClientId: clientID},
		Token:  tokenValue,
	})
}

// introspect authenticates the client then exercises the introspection
// endpoint.
func (h *harness) introspect(t *testing.T, clientID, tokenValue string) (*tokenv1.IntrospectResponse, error) {
	t.Helper()

	h.authenticateClient(t, clientID)
	return h.tokenz.Introspect(context.Background(), &tokenv1.IntrospectRequest{
		Issuer: h.issuer,
		Client: &clientv1.Client{ClientId: clientID},
		Token:  tokenValue,
	})
}

// asSigningKey is the ES384 P-384 fixture used to sign JAR request objects
// in the integration tests; the authorization server verifies them with the
// matching public key.
var asSigningKey = func() jwk.Key {
	pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	key, err := jwxjwk.Import(pk)
	if err != nil {
		panic(err)
	}
	if err := key.Set(jwxjwk.KeyIDKey, "as-jar-key"); err != nil {
		panic(err)
	}
	if err := key.Set(jwxjwk.AlgorithmKey, "ES384"); err != nil {
		panic(err)
	}
	return key
}()

// jarVerifier assembles the JAR request-object verifier: ES384 signatures
// checked against the fixture AS signing key.
func jarVerifier() sdktoken.Verifier {
	pub, err := jwxjwk.PublicKeyOf(asSigningKey)
	if err != nil {
		panic(err)
	}
	set := jwxjwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		panic(err)
	}
	return jwt.DefaultVerifier(func(_ context.Context) (jwk.Set, error) {
		return set, nil
	}, []string{"ES384"})
}

// jarDecoder builds the JAR request-object decoder bound to the test issuer.
func jarDecoder() jwsreq.AuthorizationDecoder {
	return jwsreq.AuthorizationRequestDecoder(jarVerifier(), testIssuer)
}

// signedRequestObject signs an arbitrary claim set with the AS fixture key as
// a JAR request object.
func signedRequestObject(t *testing.T, claims map[string]any) string {
	t.Helper()

	var rawKey any
	if err := jwxjwk.Export(asSigningKey, &rawKey); err != nil {
		t.Fatalf("unable to materialize AS signing key: %v", err)
	}

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES384, gojwt.MapClaims(claims))
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to serialize request object: %v", err)
	}
	return raw
}

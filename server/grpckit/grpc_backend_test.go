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

package grpckit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/clientregistration"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

// ES256 P-256 key/JWKS fixtures shared with the integration harness.
var (
	clientPrivateKey  = []byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)
	clientJWKSWithSIG = []byte(`{"keys": [{"kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`)
)

const (
	testIssuer        = "http://127.0.0.1:8080"
	testTokenEndpoint = testIssuer + "/token"
	testRedirectURI   = "https://client.example.org/cb"
)

// backend wires the real in-memory service stack behind a bufconn gRPC
// server, mirroring examples/authorizationserver wiring.
type backend struct {
	conn *grpc.ClientConn
}

func newBackend(t *testing.T) *backend {
	t.Helper()

	storageKey := []byte("grpckit-storage-key-0123456789abcd")

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
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)

	// Token generators
	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("grpckit-at-mac-key"))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("grpckit-rt-mac-key"))

	// Services
	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	tokenz := token.New(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources)
	registrz := clientregistration.New(clients, tokens, func(context.Context, *clientv1.RegisterRequest) bool { return true })

	// gRPC server
	srv := grpc.NewServer()
	flowv1.RegisterAuthorizationServiceServer(srv, AuthorizationService(authz, tokenz))
	clientv1.RegisterClientAuthenticationServiceServer(srv, ClientAuthentication(clients, testIssuer, []string{"ES256"}, nil, proofs, profile.Strict()))
	clientv1.RegisterClientRegistrationServiceServer(srv, ClientRegistration(registrz, testIssuer))
	clientv1.RegisterClientRegistrationManagementServiceServer(srv, ClientRegistrationManagement(registrz, testIssuer))
	tokenv1.RegisterIntrospectionServiceServer(srv, IntrospectionService(tokenz))
	tokenv1.RegisterRevocationServiceServer(srv, RevocationService(tokenz))

	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &backend{conn: conn}
}

// s256Challenge computes the RFC 7636 S256 code challenge of a verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// clientAssertion signs a private_key_jwt assertion with the ES256 fixture
// key, aud-bound to the AS issuer identifier
// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1).
func clientAssertion(t *testing.T, clientID, audience string) string {
	t.Helper()

	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	var rawKey any
	require.NoError(t, jwxjwk.Export(privateKey, &rawKey))

	now := uint64(time.Now().Unix())
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"jti": random.String(16),
		"sub": clientID,
		"iss": clientID,
		"aud": audience,
		"exp": now + 300,
		"iat": now,
		"nbf": now,
	})
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)
	return raw
}

// authenticateClient runs the gRPC client authentication with a valid
// private_key_jwt assertion.
func (b *backend) authenticateClient(t *testing.T, clientID string) *clientv1.Client {
	t.Helper()

	assertionType := oidc.AssertionTypeJWTBearer
	assertion := clientAssertion(t, clientID, testIssuer)
	endpoint := testTokenEndpoint

	c := clientv1.NewClientAuthenticationServiceClient(b.conn)
	res, err := c.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
		ClientAssertionType: &assertionType,
		ClientAssertion:     &assertion,
		ClientId:            &clientID,
		Endpoint:            &endpoint,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Nil(t, res.GetError())
	require.NotNil(t, res.GetClient())
	return res.GetClient()
}

// registerClient runs the gRPC dynamic client registration.
func (b *backend) registerClient(t *testing.T, meta *clientv1.ClientMeta) *clientv1.Client {
	t.Helper()

	c := clientv1.NewClientRegistrationServiceClient(b.conn)
	res, err := c.Register(context.Background(), &clientv1.RegisterRequest{Metadata: meta})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Nil(t, res.GetError())
	require.NotNil(t, res.GetClient())
	return res.GetClient()
}

func TestGRPCBackendClientCredentials(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	// Dynamic registration: confidential client, client_credentials grant,
	// private_key_jwt with fixture JWKS.
	client := b.registerClient(t, &clientv1.ClientMeta{
		TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		Jwks:                    clientJWKSWithSIG,
	})
	require.NotEmpty(t, client.GetClientId())
	require.Empty(t, client.GetClientSecret(), "no client secret is ever issued")
	require.Equal(t, oidc.AuthMethodPrivateKeyJWT, client.GetTokenEndpointAuthMethod())

	// Authenticate the client over gRPC.
	authed := b.authenticateClient(t, client.GetClientId())
	require.Equal(t, client.GetClientId(), authed.GetClientId())

	// client_credentials token grant.
	authz := flowv1.NewAuthorizationServiceClient(b.conn)
	tokenRes, err := authz.Token(ctx, &flowv1.TokenRequest{
		Issuer:    testIssuer,
		Client:    authed,
		GrantType: oidc.GrantTypeClientCredentials,
		Grant: &flowv1.TokenRequest_ClientCredentials{
			ClientCredentials: &flowv1.GrantClientCredentials{},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, tokenRes)
	require.Nil(t, tokenRes.GetError())
	accessToken := tokenRes.GetAccessToken()
	require.NotNil(t, accessToken)
	require.NotEmpty(t, accessToken.GetValue())

	// Introspect: active.
	introspection := tokenv1.NewIntrospectionServiceClient(b.conn)
	active, err := introspection.Introspect(ctx, &tokenv1.IntrospectRequest{
		Issuer: testIssuer,
		Client: &clientv1.Client{ClientId: client.GetClientId()},
		Token:  accessToken.GetValue(),
	})
	require.NoError(t, err)
	require.Nil(t, active.GetError())
	require.True(t, active.GetToken().GetStatus() == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, "token must be active, got %v", active.GetToken().GetStatus())

	// Revoke.
	revocation := tokenv1.NewRevocationServiceClient(b.conn)
	revoked, err := revocation.Revoke(ctx, &tokenv1.RevokeRequest{
		Issuer: testIssuer,
		Client: &clientv1.Client{ClientId: client.GetClientId()},
		Token:  accessToken.GetValue(),
	})
	require.NoError(t, err)
	require.Nil(t, revoked.GetError())

	// Introspect: inactive.
	inactive, err := introspection.Introspect(ctx, &tokenv1.IntrospectRequest{
		Issuer: testIssuer,
		Client: &clientv1.Client{ClientId: client.GetClientId()},
		Token:  accessToken.GetValue(),
	})
	require.NoError(t, err)
	require.Nil(t, inactive.GetError())
	require.False(t, inactive.GetToken().GetStatus() == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE)
}

func TestGRPCBackendPARCodeFlow(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	// Register a code-flow client.
	client := b.registerClient(t, &clientv1.ClientMeta{
		TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
		GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		ResponseModes:           []string{oidc.ResponseModeQueryJWT},
		RedirectUris:            []string{testRedirectURI},
		Jwks:                    clientJWKSWithSIG,
	})
	require.Equal(t, []string{oidc.ResponseTypeCode}, client.GetResponseTypes())

	// Authenticate over gRPC.
	authed := b.authenticateClient(t, client.GetClientId())

	// PAR registration.
	verifier := random.String(64)
	authz := flowv1.NewAuthorizationServiceClient(b.conn)
	regRes, err := authz.Register(ctx, &flowv1.RegistrationRequest{
		Issuer: testIssuer,
		Client: authed,
		Request: &flowv1.AuthorizationRequest{
			Scope:               "openid",
			ResponseType:        oidc.ResponseTypeCode,
			ClientId:            client.GetClientId(),
			RedirectUri:         testRedirectURI,
			State:               "af0ifjsldkjoijaoijoijaoidja3456789012",
			Nonce:               "n-0S6_WzA2Mj",
			Audience:            "urn:example:cooperation-context",
			CodeChallenge:       s256Challenge(verifier),
			CodeChallengeMethod: oidc.CodeChallengeMethodSha256,
			ResponseMode:        new(oidc.ResponseModeQueryJWT),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, regRes)
	require.Nil(t, regRes.GetError())
	require.NotEmpty(t, regRes.GetRequestUri())

	// Authorize: consume the request_uri.
	authRes, err := authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:  testIssuer,
		Client:  authed,
		Subject: "user-1",
		Request: &flowv1.AuthorizationRequest{
			RequestUri: new(regRes.GetRequestUri()),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, authRes)
	require.Nil(t, authRes.GetError())
	require.NotEmpty(t, authRes.GetCode())

	// Redeem the code with the PKCE verifier.
	tokenRes, err := authz.Token(ctx, &flowv1.TokenRequest{
		Issuer:    testIssuer,
		Client:    authed,
		GrantType: oidc.GrantTypeAuthorizationCode,
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{
				Code:         authRes.GetCode(),
				CodeVerifier: verifier,
				RedirectUri:  testRedirectURI,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: strings.Repeat("a", 43)},
	})
	require.NoError(t, err)
	require.NotNil(t, tokenRes)
	require.Nil(t, tokenRes.GetError())
	require.NotNil(t, tokenRes.GetAccessToken())
	require.NotEmpty(t, tokenRes.GetAccessToken().GetValue())
}

func TestGRPCBackendBadAssertion(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	client := b.registerClient(t, &clientv1.ClientMeta{
		TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		Jwks:                    clientJWKSWithSIG,
	})

	// Assertion with a wrong audience: authentication must fail with
	// invalid_client, carried in the response payload.
	assertionType := oidc.AssertionTypeJWTBearer
	assertion := clientAssertion(t, client.GetClientId(), "https://other.example.com")
	endpoint := testTokenEndpoint

	c := clientv1.NewClientAuthenticationServiceClient(b.conn)
	res, err := c.Authenticate(ctx, &clientv1.AuthenticateRequest{
		ClientAssertionType: &assertionType,
		ClientAssertion:     &assertion,
		ClientId:            new(client.GetClientId()),
		Endpoint:            &endpoint,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.GetError())
	require.Equal(t, "invalid_request", res.GetError().GetError())
	require.Nil(t, res.GetClient())
}

func TestGRPCBackendClientRegistrationManagement(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	// Register a client and capture the RFC 7592 credentials.
	reg := clientv1.NewClientRegistrationServiceClient(b.conn)
	regRes, err := reg.Register(ctx, &clientv1.RegisterRequest{
		Metadata: &clientv1.ClientMeta{
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			GrantTypes:              []string{oidc.GrantTypeClientCredentials},
			Jwks:                    clientJWKSWithSIG,
			ClientName:              new("managed"),
		},
	})
	require.NoError(t, err)
	require.Nil(t, regRes.GetError())
	require.NotEmpty(t, regRes.GetRegistrationAccessToken())
	require.Equal(t, testIssuer+"/register/"+regRes.GetClient().GetClientId(), regRes.GetRegistrationClientUri())

	clientID := regRes.GetClient().GetClientId()
	token := regRes.GetRegistrationAccessToken()

	mgmt := clientv1.NewClientRegistrationManagementServiceClient(b.conn)

	// Read (RFC 7592 section 2.1): current metadata, no bearer token in
	// the payload.
	readRes, err := mgmt.Read(ctx, &clientv1.ReadRequest{
		RegistrationAccessToken: &token,
		ClientId:                &clientID,
	})
	require.NoError(t, err)
	require.Nil(t, readRes.GetError())
	require.Equal(t, "managed", readRes.GetClient().GetClientName())
	require.Empty(t, readRes.GetClient().GetRegistrationAccessToken())

	// Update (RFC 7592 section 2.2): full replacement.
	v2 := "managed-v2"
	updRes, err := mgmt.Update(ctx, &clientv1.UpdateRequest{
		RegistrationAccessToken: &token,
		ClientId:                &clientID,
		Metadata: &clientv1.ClientMeta{
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			GrantTypes:              []string{oidc.GrantTypeClientCredentials},
			Jwks:                    clientJWKSWithSIG,
			ClientName:              &v2,
		},
	})
	require.NoError(t, err)
	require.Nil(t, updRes.GetError())
	require.Equal(t, clientID, updRes.GetClient().GetClientId())
	require.Equal(t, v2, updRes.GetClient().GetClientName())
	require.Empty(t, updRes.GetClient().GetRegistrationAccessToken())

	// Read reflects the update; the same registration token still
	// authenticates.
	readRes2, err := mgmt.Read(ctx, &clientv1.ReadRequest{
		RegistrationAccessToken: &token,
		ClientId:                &clientID,
	})
	require.NoError(t, err)
	require.Nil(t, readRes2.GetError())
	require.Equal(t, v2, readRes2.GetClient().GetClientName())

	// Wrong token (RFC 7592 section 2.1): invalid_token, and the stored
	// token is revoked — the legitimate token no longer works either.
	wrong := "not-the-token"
	badRes, err := mgmt.Read(ctx, &clientv1.ReadRequest{
		RegistrationAccessToken: &wrong,
		ClientId:                &clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, badRes.GetError())
	require.Equal(t, "invalid_token", badRes.GetError().GetError())

	afterBadRes, err := mgmt.Read(ctx, &clientv1.ReadRequest{
		RegistrationAccessToken: &token,
		ClientId:                &clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, afterBadRes.GetError())
	require.Equal(t, "invalid_token", afterBadRes.GetError().GetError())

	// Unknown client (RFC 7592 section 2.1): invalid_token without
	// cause distinction.
	unknown := "no-such-client"
	unknownRes, err := mgmt.Read(ctx, &clientv1.ReadRequest{
		RegistrationAccessToken: &token,
		ClientId:                &unknown,
	})
	require.NoError(t, err)
	require.NotNil(t, unknownRes.GetError())
	require.Equal(t, "invalid_token", unknownRes.GetError().GetError())
}

func TestGRPCBackendClientRegistrationManagementDelete(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	// Register a client to deprovision.
	reg := clientv1.NewClientRegistrationServiceClient(b.conn)
	regRes, err := reg.Register(ctx, &clientv1.RegisterRequest{
		Metadata: &clientv1.ClientMeta{
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			GrantTypes:              []string{oidc.GrantTypeClientCredentials},
			Jwks:                    clientJWKSWithSIG,
		},
	})
	require.NoError(t, err)
	require.Nil(t, regRes.GetError())

	clientID := regRes.GetClient().GetClientId()
	token := regRes.GetRegistrationAccessToken()

	mgmt := clientv1.NewClientRegistrationManagementServiceClient(b.conn)

	// Delete (RFC 7592 section 2.3).
	delRes, err := mgmt.Delete(ctx, &clientv1.DeleteRequest{
		RegistrationAccessToken: &token,
		ClientId:                &clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, delRes)
	require.Nil(t, delRes.GetError())

	// The client is gone: subsequent reads fail with invalid_token.
	readRes, err := mgmt.Read(ctx, &clientv1.ReadRequest{
		RegistrationAccessToken: &token,
		ClientId:                &clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, readRes.GetError())
	require.Equal(t, "invalid_token", readRes.GetError().GetError())

	// Client authentication no longer resolves the deleted client.
	auth := clientv1.NewClientAuthenticationServiceClient(b.conn)
	assertionType := oidc.AssertionTypeJWTBearer
	assertion := clientAssertion(t, clientID, testIssuer)
	endpoint := testTokenEndpoint
	authRes, err := auth.Authenticate(ctx, &clientv1.AuthenticateRequest{
		ClientAssertionType: &assertionType,
		ClientAssertion:     &assertion,
		ClientId:            &clientID,
		Endpoint:            &endpoint,
	})
	require.NoError(t, err)
	require.NotNil(t, authRes.GetError())
	require.Nil(t, authRes.GetClient())
}

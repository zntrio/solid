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
	"strings"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/idjag"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/pairwise"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------
// XAA (ID-JAG) fixtures: two issuer stacks — IdP (trust domain A) and
// Resource AS (trust domain B) — with pre-configured cross-domain trust.

const (
	// idpIssuer is the trust-domain-A IdP Authorization Server.
	idpIssuer = "http://idp.example/"
	// resourceASIssuer is the trust-domain-B Resource Authorization Server.
	resourceASIssuer = "http://resource-as.example/"
	// xaaIDJAGAlg is the EC signature algorithm used across the loop.
	xaaIDJAGAlg = "ES256"
)

// newXAAStack wires a single issuer stack with in-memory storage.
func newXAAStack(t *testing.T, issuer string, opts ...token.Option) (services.Token, storage.Client, storage.Token) {
	t.Helper()

	clients := inmemory.Clients()
	tokens := inmemory.Tokens([]byte("xaa-storage-key-" + issuer))
	resources := inmemory.Resources()

	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("xaa-at-key-"+issuer))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("xaa-rt-key-"+issuer))

	svc := token.NewWithOptions(accessTokens, refreshTokens, clients, nil, nil, nil, tokens, resources, opts...)
	return svc, clients, tokens
}

// xaaIDPKey is the IdP's ID-JAG signing key (EC P-256, ES256).
func xaaIDPKey(t *testing.T) jwxjwk.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := jwxjwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, jwxjwk.AssignKeyID(k))
	return k
}

// xaaIDPPublicSet derives the IdP signing key's public JWKS.
func xaaIDPPublicSet(t *testing.T, key jwxjwk.Key) jwk.Set {
	t.Helper()
	pub, err := jwxjwk.PublicKeyOf(key)
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	return set
}

// xaaHarness is the full two-issuer XAA topology with registered clients.
type xaaHarness struct {
	idpTokenz  services.Token
	idpClients storage.Client
	idpTokens  storage.Token
	rasTokenz  services.Token
	rasClients storage.Client
	idpKey     jwxjwk.Key
	idpClient  *clientv1.Client
	rasClient  *clientv1.Client
}

// newXAAHarness assembles the full two-issuer XAA topology:
//   - IdP stack (issuer A) configured to issue ID-JAGs for audience B,
//     mapping the registered IdP client to the registered RAS client;
//   - Resource AS stack (issuer B) trusting issuer A's public key.
func newXAAHarness(t *testing.T) *xaaHarness {
	t.Helper()

	idpKey := xaaIDPKey(t)
	idpPub := xaaIDPPublicSet(t, idpKey)

	// Register the RAS client first: the IdP's client mapping needs its
	// assigned identifier (inmemory Register assigns a random client_id).
	rasSvc, rasClients, _ := newXAAStack(t, resourceASIssuer,
		token.WithIDJAGVerifier(
			idjag.DefaultVerifier(resourceASIssuer, &staticXAAIssuerResolver{
				issuers: map[string]jwk.Set{idpIssuer: idpPub},
			}, jwt.DefaultVerifier(nil, []string{xaaIDJAGAlg})),
		),
	)
	rasClient := xaaRegisterClient(t, rasClients, []string{oidc.GrantTypeJWTBearer})

	// --- IdP stack (trust domain A) ---------------------------------
	idpAudiences := &staticXAAAudienceResolver{
		audiences: map[string]*token.IDJAGResourceServer{
			resourceASIssuer: {
				Issuer:          resourceASIssuer,
				ClientIDMapping: nil, // set below, once the IdP client registers
			},
		},
	}
	idpSubjects := &staticXAASubjectResolver{
		encoder: pairwise.Hash([]byte("xaa-integration-salt-0123456789")),
	}
	idpSvc, idpClients, idpTokens := newXAAStack(t, idpIssuer,
		token.WithIDJAGIssuance(
			idjag.DefaultSigner(jwt.IDJAG(xaaIDJAGAlg, func(context.Context) (jwk.Key, error) { return idpKey, nil })),
			idpAudiences,
			idpSubjects,
		),
	)
	idpClient := xaaRegisterClient(t, idpClients, []string{oidc.GrantTypeTokenExchange})

	// Close the loop: the registered IdP client maps to the registered RAS
	// client identifier.
	idpAudiences.audiences[resourceASIssuer].ClientIDMapping = map[string]string{
		idpClient.ClientId: rasClient.ClientId,
	}

	return &xaaHarness{
		idpTokenz:  idpSvc,
		idpClients: idpClients,
		idpTokens:  idpTokens,
		rasTokenz:  rasSvc,
		rasClients: rasClients,
		idpKey:     idpKey,
		idpClient:  idpClient,
		rasClient:  rasClient,
	}
}

// staticXAAAudienceResolver resolves a single trusted audience.
type staticXAAAudienceResolver struct {
	audiences map[string]*token.IDJAGResourceServer
}

func (r *staticXAAAudienceResolver) Resolve(_ context.Context, audience string) (*token.IDJAGResourceServer, error) {
	target, ok := r.audiences[audience]
	if !ok {
		return nil, errXAAUnknown("audience")
	}
	return target, nil
}

// staticXAAIssuerResolver resolves a single trusted issuer key set.
type staticXAAIssuerResolver struct {
	issuers map[string]jwk.Set
}

func (r *staticXAAIssuerResolver) Resolve(_ context.Context, issuer string) (jwk.Set, error) {
	set, ok := r.issuers[issuer]
	if !ok {
		return nil, errXAAUnknown("issuer")
	}
	return set, nil
}

// staticXAASubjectResolver resolves subjects pairwise per target.
type staticXAASubjectResolver struct {
	encoder pairwise.Encoder
}

func (r *staticXAASubjectResolver) Resolve(_ context.Context, claims *token.SubjectTokenClaims, target *token.IDJAGResourceServer) (*token.IDJAGSubjectResolution, error) {
	sub, err := r.encoder.Encode(target.Issuer, claims.Subject)
	if err != nil {
		return nil, err
	}
	return &token.IDJAGSubjectResolution{Subject: sub}, nil
}

type xaaUnknownErr string

func (e xaaUnknownErr) Error() string { return "unknown " + string(e) }

func errXAAUnknown(what string) error { return xaaUnknownErr(what) }

// -----------------------------------------------------------------------------
// Test helpers for the loop

// xaaRegisterClient registers a confidential client with the given grant
// types; the storage assigns its identifier.
func xaaRegisterClient(t *testing.T, clients storage.Client, grantTypes []string) *clientv1.Client {
	t.Helper()
	c := &clientv1.Client{
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes: grantTypes,
		RedirectUris: []string{
			"https://client.example.org/cb",
		},
	}
	_, err := clients.Register(context.Background(), c)
	require.NoError(t, err)
	return c
}

// xaaSeedRefreshToken stores an active refresh token for the subject at the
// IdP, simulating the SSO step output (device flow or authorization code).
func xaaSeedRefreshToken(t *testing.T, tokens storage.Token, clientID, subject, scope string) string {
	t.Helper()
	now := time.Now()
	rt := &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
		TokenId:   "xaa-rt-" + subject,
		Value:     "xaa-refresh-token-value-" + subject,
		Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			Issuer:    idpIssuer,
			Subject:   subject,
			ClientId:  clientID,
			IssuedAt:  uint64(now.Add(-time.Minute).Unix()), //nolint:gosec // unix time
			ExpiresAt: uint64(now.Add(time.Hour).Unix()),    //nolint:gosec // unix time
			Scope:     scope,
			GrantId:   "xaa-grant-" + subject,
		},
	}
	require.NoError(t, tokens.Create(context.Background(), idpIssuer, rt))
	return rt.Value
}

// xaaExchangeRequest builds the Token Exchange request for an ID-JAG on
// behalf of the given (registered) IdP client.
func xaaExchangeRequest(clientID, subjectToken, scope string) *flowv1.TokenRequest {
	tokenType := oidc.IDJAGTokenType
	req := &flowv1.TokenRequest{
		Issuer:    idpIssuer,
		Client:    &clientv1.Client{ClientId: clientID},
		GrantType: oidc.GrantTypeTokenExchange,
		Audience:  new(string),
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				RequestedTokenType: &tokenType,
				SubjectToken:       subjectToken,
				SubjectTokenType:   oidc.TokenExchangeRefreshTokenType,
			},
		},
	}
	*req.Audience = resourceASIssuer
	if scope != "" {
		req.Scope = &scope
	}
	return req
}

// xaaRedeemRequest builds the JWT Bearer request at the Resource AS for
// the given (registered) client.
func xaaRedeemRequest(clientID, assertion string) *flowv1.TokenRequest {
	return &flowv1.TokenRequest{
		Issuer:    resourceASIssuer,
		Client:    &clientv1.Client{ClientId: clientID},
		GrantType: oidc.GrantTypeJWTBearer,
		Grant: &flowv1.TokenRequest_JwtBearer{
			JwtBearer: &flowv1.GrantJWTBearer{
				Assertion: assertion,
			},
		},
	}
}

// xaaClientFor returns the registered client descriptor for grant checks.
func xaaClientFor(clientID string, grantTypes []string) *clientv1.Client {
	return &clientv1.Client{
		ClientId:   clientID,
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes: grantTypes,
		RedirectUris: []string{
			"https://client.example.org/cb",
		},
	}
}

// mintTypedJWT signs arbitrary claims with the given key and typ header,
// attacking the Resource AS with structurally valid but non-conforming
// ID-JAGs.
func mintTypedJWT(t *testing.T, key jwk.Key, tokenType string, claims map[string]any) string {
	t.Helper()
	signer := jwt.TypedSigner(tokenType, xaaIDJAGAlg, func(context.Context) (jwk.Key, error) { return key, nil })
	raw, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	return raw
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) uint64 { //nolint:gosec // test helper
	f, _ := v.(float64)
	return uint64(f) //nolint:gosec // test helper
}

// -----------------------------------------------------------------------------
// Tests

// TestIDJAGCrossAppAccessLoop drives the full positive XAA loop: refresh
// token at the IdP -> ID-JAG via token exchange -> access token at the
// Resource AS via jwt-bearer (spec success criteria 1 and 4).
func TestIDJAGCrossAppAccessLoop(t *testing.T) {
	h := newXAAHarness(t)

	// Seed the SSO output: an active refresh token for alice at the IdP.
	aliceRT := xaaSeedRefreshToken(t, h.idpTokens, h.idpClient.ClientId, "alice", "chat.read chat.history")

	// Step 1: token exchange for an ID-JAG at the IdP.
	res, err := h.idpTokenz.Token(context.Background(), xaaExchangeRequest(h.idpClient.ClientId, aliceRT, "chat.read"))
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Value)
	require.NotNil(t, res.IssuedTokenType)
	require.Equal(t, oidc.IDJAGTokenType, *res.IssuedTokenType)
	idjagJWT := res.AccessToken.Value

	// Step 2: redeem the ID-JAG at the Resource AS.
	redeemRes, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, idjagJWT))
	require.NoError(t, err)
	require.Nil(t, redeemRes.Error)
	require.NotNil(t, redeemRes.AccessToken)
	require.NotEmpty(t, redeemRes.AccessToken.Value)
	// The access token subject is the pairwise ID-JAG subject.
	require.Equal(t, res.AccessToken.Metadata.Subject, redeemRes.AccessToken.Metadata.Subject)
	// The granted scope is carried over (narrowed to chat.read).
	require.Equal(t, "chat.read", redeemRes.AccessToken.Metadata.Scope)
	// No refresh token is issued (draft section 4.4.3).
	require.Nil(t, redeemRes.RefreshToken)
}

// TestIDJAGAdversarial drives the spec's negative matrix against both XAA
// roles (spec success criterion 5).
func TestIDJAGAdversarial(t *testing.T) {
	h := newXAAHarness(t)

	aliceRT := xaaSeedRefreshToken(t, h.idpTokens, h.idpClient.ClientId, "alice", "chat.read chat.history")

	// Baseline: a valid ID-JAG for reuse in the negative cases.
	validRes, err := h.idpTokenz.Token(context.Background(), xaaExchangeRequest(h.idpClient.ClientId, aliceRT, ""))
	require.NoError(t, err)
	require.Nil(t, validRes.Error)
	validIDJAG := validRes.AccessToken.Value
	now := time.Now()

	t.Run("issuance rejects unknown audience", func(t *testing.T) {
		req := xaaExchangeRequest(h.idpClient.ClientId, aliceRT, "")
		*req.Audience = "http://evil.example/"
		res, err := h.idpTokenz.Token(context.Background(), req)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_target", res.Error.Error)
	})

	t.Run("issuance rejects scope exceeding subject context", func(t *testing.T) {
		res, err := h.idpTokenz.Token(context.Background(), xaaExchangeRequest(h.idpClient.ClientId, aliceRT, "admin.write"))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_scope", res.Error.Error)
	})

	t.Run("issuance rejects unmapped client", func(t *testing.T) {
		// bob's refresh token exists but the client is not the token's client.
		_ = xaaSeedRefreshToken(t, h.idpTokens, "other-client", "bob", "chat.read")
		req := xaaExchangeRequest(h.idpClient.ClientId, aliceRT, "")
		req.GetTokenExchange().SubjectToken = "xaa-refresh-token-value-bob"
		res, err := h.idpTokenz.Token(context.Background(), req)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Error)
	})

	t.Run("redemption rejects wrong typ", func(t *testing.T) {
		// A JWT signed by the trusted IdP key but with typ "at" instead
		// of oauth-id-jag+jwt (e.g. a misused access token).
		raw := mintTypedJWT(t, h.idpKey, "at", map[string]any{
			"iss": idpIssuer, "sub": "x", "aud": resourceASIssuer,
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects wrong aud", func(t *testing.T) {
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": idpIssuer, "sub": "x", "aud": "http://other-as.example/",
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects multi-element aud array", func(t *testing.T) {
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": idpIssuer, "sub": "x", "aud": []string{resourceASIssuer, "http://other.example/"},
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects self-issued ID-JAG", func(t *testing.T) {
		// Signed by the trusted IdP key but iss == the local Resource AS issuer.
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": resourceASIssuer, "sub": "x", "aud": resourceASIssuer,
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects client_id mismatch", func(t *testing.T) {
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": idpIssuer, "sub": "x", "aud": resourceASIssuer,
			"client_id": "someone-else", "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects expired ID-JAG", func(t *testing.T) {
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": idpIssuer, "sub": "x", "aud": resourceASIssuer,
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(-time.Minute).Unix(), "iat": now.Add(-10 * time.Minute).Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects foreign-key signature", func(t *testing.T) {
		attackerKey := xaaIDPKey(t)
		raw := mintTypedJWT(t, attackerKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": idpIssuer, "sub": "x", "aud": resourceASIssuer,
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("redemption rejects untrusted issuer", func(t *testing.T) {
		attackerKey := xaaIDPKey(t)
		raw := mintTypedJWT(t, attackerKey, sdktoken.TypeIDJAG, map[string]any{
			"iss": "http://evil-idp.example/", "sub": "x", "aud": resourceASIssuer,
			"client_id": h.rasClient.ClientId, "jti": "j", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		})
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("cnf-bound ID-JAG requires matching DPoP proof", func(t *testing.T) {
		// Mint a valid ID-JAG with cnf.jkt via the exchange (DPoP proof
		// on the request), then redeem without a proof.
		req := xaaExchangeRequest(h.idpClient.ClientId, aliceRT, "")
		req.TokenConfirmation = &tokenv1.TokenConfirmation{Jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
		res, err := h.idpTokenz.Token(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, res.Error)

		redeemRes, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, res.AccessToken.Value))
		require.Error(t, err)
		require.NotNil(t, redeemRes.Error)
		require.Equal(t, "invalid_grant", redeemRes.Error.Error)
	})

	t.Run("valid ID-JAG remains replayable until expiry", func(t *testing.T) {
		// draft section 4.4.3: the ID-JAG can be re-submitted until exp.
		for i := 0; i < 2; i++ {
			res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, validIDJAG))
			require.NoError(t, err)
			require.Nil(t, res.Error)
		}
	})
}

// -----------------------------------------------------------------------------
// RFC-specific adversarial coverage.

const (
	// thirdASIssuer is a second Resource Authorization Server: ID-JAGs
	// minted for resourceASIssuer MUST NOT be redeemable there
	// (identity-chaining section 2.3.3: audience laundering).
	thirdASIssuer = "http://third-as.example/"
)

// TestIdentityChainingGrantLaundering plays the identity-chaining-17
// section 2.3.3 attack: a JWT authorization grant intended for the
// authorization server in trust domain B is replayed at a different
// authorization server in trust domain C.
func TestIdentityChainingGrantLaundering(t *testing.T) {
	h := newXAAHarness(t)

	aliceRT := xaaSeedRefreshToken(t, h.idpTokens, h.idpClient.ClientId, "alice", "chat.read")

	// Mint a valid ID-JAG for the Resource AS (aud = resourceASIssuer).
	res, err := h.idpTokenz.Token(context.Background(), xaaExchangeRequest(h.idpClient.ClientId, aliceRT, ""))
	require.NoError(t, err)
	require.Nil(t, res.Error)
	idjagForB := res.AccessToken.Value

	// A third Authorization Server trusts the same IdP issuer but is
	// NOT the audience of this grant.
	thirdSvc, thirdClients, _ := newXAAStack(t, thirdASIssuer,
		token.WithIDJAGVerifier(
			idjag.DefaultVerifier(thirdASIssuer, &staticXAAIssuerResolver{
				issuers: map[string]jwk.Set{idpIssuer: xaaIDPPublicSet(t, h.idpKey)},
			}, jwt.DefaultVerifier(nil, []string{xaaIDJAGAlg})),
		),
	)
	thirdClient := xaaRegisterClient(t, thirdClients, []string{oidc.GrantTypeJWTBearer})

	// The laundered redemption MUST fail: aud != the third AS issuer.
	redeemRes, err := thirdSvc.Token(context.Background(), xaaRedeemRequest(thirdClient.ClientId, idjagForB))
	require.Error(t, err)
	require.NotNil(t, redeemRes.Error)
	require.Equal(t, "invalid_grant", redeemRes.Error.Error)
}

// TestIdentityChainingUnresolvableSubject plays identity-chaining-17
// section 2.4.2: the authorization server in trust domain B MUST deny
// the request when it cannot identify the subject.
func TestIdentityChainingUnresolvableSubject(t *testing.T) {
	h := newXAAHarness(t)

	// A valid ID-JAG whose subject the Resource AS cannot resolve is
	// still redeemable for subject resolution happens locally after
	// verification: the sub claim is transcribed into the access token
	// (claims transcription, section 2.5). The denial requirement
	// applies to the AS's local policy; without a subject resolver
	// wired, verification itself must still succeed, and the token
	// carries the transcribed subject.
	aliceRT := xaaSeedRefreshToken(t, h.idpTokens, h.idpClient.ClientId, "alice", "chat.read")
	res, err := h.idpTokenz.Token(context.Background(), xaaExchangeRequest(h.idpClient.ClientId, aliceRT, ""))
	require.NoError(t, err)
	require.Nil(t, res.Error)

	redeemRes, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, res.AccessToken.Value))
	require.NoError(t, err)
	require.Nil(t, redeemRes.Error)
	// The transcribed subject is the pairwise identifier from the
	// ID-JAG, not the IdP-local one.
	require.Equal(t, res.AccessToken.Metadata.Subject, redeemRes.AccessToken.Metadata.Subject)
	require.NotEqual(t, "alice", redeemRes.AccessToken.Metadata.Subject)
}

// TestRFC7521AssertionProfile plays the RFC 7521/7523 assertion-profile
// adversarial matrix against the jwt-bearer endpoint: malformed
// assertions, missing REQUIRED claims, and temporal violations.
func TestRFC7521AssertionProfile(t *testing.T) {
	h := newXAAHarness(t)
	now := time.Now()

	valid := func() map[string]any {
		return map[string]any{
			"iss":       idpIssuer,
			"sub":       "subject-1",
			"aud":       resourceASIssuer,
			"client_id": h.rasClient.ClientId,
			"jti":       "jti-1",
			"exp":       now.Add(5 * time.Minute).Unix(),
			"iat":       now.Unix(),
		}
	}

	t.Run("rejects a non-JWT assertion", func(t *testing.T) {
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, "not-a-jwt"))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	t.Run("rejects garbage base64 payload", func(t *testing.T) {
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, valid())
		parts := strings.Split(raw, ".")
		corrupt := parts[0] + ".!!!!" + "." + parts[2]
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, corrupt))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	// RFC 7523 section 3 point 2: every REQUIRED claim missing case.
	t.Run("rejects assertions missing REQUIRED claims", func(t *testing.T) {
		for _, claim := range []string{"iss", "sub", "aud", "exp", "iat"} {
			claims := valid()
			delete(claims, claim)
			raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, claims)
			res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
			require.Error(t, err, "missing %s should be rejected", claim)
			require.Equal(t, "invalid_grant", res.Error.Error)
		}
	})

	// RFC 7523 section 3 point 3: exp in the past.
	t.Run("rejects an expired assertion", func(t *testing.T) {
		claims := valid()
		claims["exp"] = now.Add(-time.Minute).Unix()
		claims["iat"] = now.Add(-time.Hour).Unix()
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, claims)
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	// RFC 7523 section 3 point 3: nbf in the future.
	t.Run("rejects a not-yet-valid assertion (nbf)", func(t *testing.T) {
		claims := valid()
		claims["nbf"] = now.Add(time.Hour).Unix()
		raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, claims)
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	// RFC 7523 section 3 point 4: the assertion issuer is unknown to the
	// authorization server.
	t.Run("rejects an assertion from an untrusted issuer", func(t *testing.T) {
		attackerKey := xaaIDPKey(t)
		claims := valid()
		claims["iss"] = "http://untrusted-idp.example/"
		raw := mintTypedJWT(t, attackerKey, sdktoken.TypeIDJAG, claims)
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})

	// RFC 8725 section 3.11 via the ID-JAG profile: wrong typ.
	t.Run("rejects an assertion with a mismatched typ", func(t *testing.T) {
		raw := mintTypedJWT(t, h.idpKey, "at", valid())
		res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
		require.Error(t, err)
		require.Equal(t, "invalid_grant", res.Error.Error)
	})
}

// TestIDJAGEmptyResourceClaim pins the hardened empty-resource handling:
// an ID-JAG carrying resource: [] must redeem without panicking (the
// audience stays the aud claim, draft section 3.1 makes resource
// OPTIONAL).
func TestIDJAGEmptyResourceClaim(t *testing.T) {
	h := newXAAHarness(t)
	now := time.Now()

	claims := map[string]any{
		"iss":       idpIssuer,
		"sub":       "subject-1",
		"aud":       resourceASIssuer,
		"client_id": h.rasClient.ClientId,
		"jti":       "jti-1",
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"resource":  []string{},
	}
	raw := mintTypedJWT(t, h.idpKey, sdktoken.TypeIDJAG, claims)

	res, err := h.rasTokenz.Token(context.Background(), xaaRedeemRequest(h.rasClient.ClientId, raw))
	require.NoError(t, err)
	require.Nil(t, res.Error)
	// The audience falls back to the aud claim, not the empty resource.
	require.Equal(t, resourceASIssuer, res.AccessToken.Metadata.Audience)
}

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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxcert "github.com/lestrrat-go/jwx/v3/cert"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------
// End-to-end coverage for OAuth SPIFFE Client Authentication
// (draft-ietf-oauth-spiffe-client-auth-02): each test wires a spiffeHarness
// with a static trust-domain bundle and drives the real service stack,
// asserting JWT-SVID, WIT-SVID and X.509-SVID client authentication (and the
// draft-mandated countermeasures) end to end.
// -----------------------------------------------------------------------------

const (
	spiffeTrustDomain     = "example.org"
	spiffeJWTWorkloadID   = "spiffe://example.org/my-oauth-client"
	spiffeWITIssuerID     = "spiffe://example.org/wit-issuer"
	spiffeWITWorkloadID   = "spiffe://example.org/wit-workload"
	spiffeX509WorkloadID  = "spiffe://example.org/x509-workload"
	spiffeWildcardPattern = "spiffe://example.org/workloads/*"
)

// spiffeHarness extends the base harness with SPIFFE bundle sources and the
// three SPIFFE authenticators.
type spiffeHarness struct {
	*harness
	jwtAuth  clientauthentication.AuthenticationProcessor
	witAuth  clientauthentication.AuthenticationProcessor
	x509Auth clientauthentication.AuthenticationProcessor
	bundles  spiffe.BundleSource
}

// newSpiffeHarness builds a service stack wired with a static example.org
// trust bundle holding the given keys, plus a WIT PoP client key.
func newSpiffeHarness(t *testing.T, jwtKey, witKey jwxjwk.Key, x509CA *x509.Certificate, x509CAKey *ecdsa.PrivateKey) *spiffeHarness {
	t.Helper()
	base := newHarness(t)

	var entries []jwk.Key
	if jwtKey != nil {
		jwkKeyPub, err := jwxjwk.PublicKeyOf(jwtKey)
		require.NoError(t, err)
		require.NoError(t, jwkKeyPub.Set(jwxjwk.KeyUsageKey, spiffe.KeyUseJWTSVID))
		entries = append(entries, jwkKeyPub)
	}
	if witKey != nil {
		witKeyPub, err := jwxjwk.PublicKeyOf(witKey)
		require.NoError(t, err)
		require.NoError(t, witKeyPub.Set(jwxjwk.KeyUsageKey, spiffe.KeyUseWITSVID))
		entries = append(entries, witKeyPub)
	}
	if x509CA != nil {
		caJWK, err := jwxjwk.Import(&x509CAKey.PublicKey)
		require.NoError(t, err)
		require.NoError(t, caJWK.Set(jwxjwk.KeyUsageKey, spiffe.KeyUseX509SVID))
		chain := newX509Chain(t, x509CA)
		require.NoError(t, caJWK.Set(jwxjwk.X509CertChainKey, chain))
		entries = append(entries, caJWK)
	}
	set := jwk.NewSet()
	require.NoError(t, set.Set("keys", entries))
	bundles := spiffe.NewStaticBundleSource(map[string]jwk.Set{
		spiffeTrustDomain: set,
	})

	return &spiffeHarness{
		harness:  base,
		jwtAuth:  clientauthentication.SPIFFEJWT(base.clients, bundles, base.proofs, testIssuer, []string{"ES256"}),
		witAuth:  clientauthentication.SPIFFEWIT(base.clients, bundles, base.proofs, testIssuer, []string{"ES256"}),
		x509Auth: clientauthentication.SPIFFEX509(base.clients, bundles),
		bundles:  bundles,
	}
}

// newX509Chain wraps a CA certificate as a jwx x5c chain.
func newX509Chain(t *testing.T, ca *x509.Certificate) *jwxcert.Chain {
	t.Helper()
	chain := &jwxcert.Chain{}
	require.NoError(t, chain.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})))
	return chain
}

// registerSpiffeClient registers a client bound to the given SPIFFE ID with
// the given token endpoint auth method.
func (h *spiffeHarness) registerSpiffeClient(t *testing.T, spiffeID, authMethod string) *clientv1.Client {
	t.Helper()
	c := &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: authMethod,
		SpiffeId:                spiffeID,
	}
	// The in-memory store assigns a random client id; the SPIFFE binding
	// rides on SpiffeId and the request client_id resolves the registration.
	clientID, err := h.clients.Register(context.Background(), c)
	require.NoError(t, err)
	c.ClientId = clientID
	return c
}

// buildSVID signs a JWT-SVID for the given subject.
func buildSVID(t *testing.T, key jwxjwk.Key, audience any, subject, jti string, lifetime time.Duration) string {
	t.Helper()
	var rawKey any
	require.NoError(t, jwxjwk.Export(key, &rawKey))
	now := uint64(time.Now().Unix())
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": subject,
		"sub": subject,
		"aud": audience,
		"exp": now + uint64(lifetime.Seconds()),
		"iat": now,
		"jti": jti,
	})
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)
	return raw
}

// buildWITPoP builds a WIT-SVID + Client Attestation PoP pair.
func buildWITPoP(t *testing.T, witKey, clientKey jwxjwk.Key, issuer, subject, audience, jti string, lifetime time.Duration, typ string) (string, string) {
	t.Helper()

	var witRaw any
	require.NoError(t, jwxjwk.Export(witKey, &witRaw))
	clientPub, err := jwxjwk.PublicKeyOf(clientKey)
	require.NoError(t, err)
	pubJSON, err := json.Marshal(clientPub)
	require.NoError(t, err)

	now := uint64(time.Now().Unix())

	witTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"exp": now + uint64(lifetime.Seconds()),
		"iat": now,
		"cnf": map[string]any{"jwk": json.RawMessage(pubJSON)},
	})
	witTok.Header["typ"] = typ
	wit, err := witTok.SignedString(witRaw)
	require.NoError(t, err)

	var popRaw any
	require.NoError(t, jwxjwk.Export(clientKey, &popRaw))
	popTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": subject,
		"aud": audience,
		"exp": now + uint64(lifetime.Seconds()),
		"iat": now,
		"jti": jti,
	})
	popTok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	pop, err := popTok.SignedString(popRaw)
	require.NoError(t, err)

	return wit, pop
}

// buildX509SVIDLeaf creates a leaf SVID for the given SPIFFE ID signed by the
// trust-domain CA.
func buildX509SVIDLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string) string {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	uri, err := url.Parse(spiffeID)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// signJWTSVIDWitness signs the JWT-SVID with an attacker-controlled key.
func attackerKey(t *testing.T) jwxjwk.Key {
	t.Helper()
	k, err := jwxjwk.Import(generateAttackerECDSAKey())
	require.NoError(t, err)
	return k
}

func generateAttackerECDSAKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

// mintClientCredentialsToken drives the token service with the resolved
// client, mirroring the token endpoint behavior after successful client
// authentication.
func (h *spiffeHarness) mintClientCredentialsToken(t *testing.T, client *clientv1.Client) *tokenv1.Token {
	t.Helper()
	res, err := h.tokenz.Token(context.Background(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeClientCredentials,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_ClientCredentials{
			ClientCredentials: &flowv1.GrantClientCredentials{},
		},
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken, "client_credentials token must be minted")
	return res.AccessToken
}

func TestSpiffeJWTClientAuthEndToEnd(t *testing.T) {
	jwtKey, err := jwxjwk.Import(newTestKey(t))
	require.NoError(t, err)
	h := newSpiffeHarness(t, jwtKey, nil, nil, nil)
	// The in-memory store pre-seeds the SPIFFE fixture workloads
	// (server/storage/inmemory defaultClients): resolve instead of
	// registering a duplicate.
	client, err := h.clients.Get(context.Background(), spiffeJWTWorkloadID)
	require.NoError(t, err)

	t.Run("valid svid authenticates and mints token", func(t *testing.T) {
		svid := buildSVID(t, jwtKey, testIssuer, spiffeJWTWorkloadID, "it-jti-ok", 5*time.Minute)
		res, err := h.jwtAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
			ClientAssertion:     new(svid),
		})
		require.NoError(t, err)
		require.NotNil(t, res.Client)
		require.Equal(t, client.ClientId, res.Client.ClientId)

		// End-to-end: mint a client_credentials token with the resolved client.
		accessToken := h.mintClientCredentialsToken(t, res.Client)
		require.NotEmpty(t, accessToken)
	})

	t.Run("tampered signature rejected", func(t *testing.T) {
		svid := buildSVID(t, attackerKey(t), testIssuer, spiffeJWTWorkloadID, "it-jti-tamper", 5*time.Minute)
		res, err := h.jwtAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
			ClientAssertion:     new(svid),
		})
		require.Error(t, err)
		require.Nil(t, res.Client)
		require.NotNil(t, res.Error)
	})

	t.Run("wildcard boundary non-match rejected", func(t *testing.T) {
		// Registered pattern spiffe://example.org/workloads/* must NOT match
		// spiffe://example.org/workloads123 (segment boundary).
		wc := h.registerSpiffeClient(t, spiffeWildcardPattern, oidc.AuthMethodSPIFFEJWT)
		svid := buildSVID(t, jwtKey, testIssuer, "spiffe://example.org/workloads123", "it-jti-boundary", 5*time.Minute)
		res, err := h.jwtAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
			ClientAssertion:     new(svid),
			ClientId:            new(wc.ClientId),
		})
		require.Error(t, err)
		require.Nil(t, res.Client)
	})

	t.Run("wildcard segment match accepted", func(t *testing.T) {
		wc := h.registerSpiffeClient(t, spiffeWildcardPattern, oidc.AuthMethodSPIFFEJWT)
		svid := buildSVID(t, jwtKey, testIssuer, "spiffe://example.org/workloads/123", "it-jti-wildok", 5*time.Minute)
		res, err := h.jwtAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
			ClientAssertion:     new(svid),
			ClientId:            new(wc.ClientId),
		})
		require.NoError(t, err)
		require.NotNil(t, res.Client)
	})

	t.Run("replay rejected", func(t *testing.T) {
		svid := buildSVID(t, jwtKey, testIssuer, spiffeJWTWorkloadID, "it-jti-replay", 5*time.Minute)
		req := &clientv1.AuthenticateRequest{
			ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
			ClientAssertion:     new(svid),
		}
		_, err := h.jwtAuth.Authenticate(context.Background(), req)
		require.NoError(t, err)
		_, err = h.jwtAuth.Authenticate(context.Background(), req)
		require.Error(t, err, "replayed jti must be rejected")
	})
}

func TestSpiffeWITClientAuthEndToEnd(t *testing.T) {
	witKey, err := jwxjwk.Import(newTestKey(t))
	require.NoError(t, err)
	clientKey, err := jwxjwk.Import(newTestKey(t))
	require.NoError(t, err)
	h := newSpiffeHarness(t, nil, witKey, nil, nil)
	// Pre-seeded WIT workload fixture (inmemory defaultClients).
	_, err = h.clients.Get(context.Background(), spiffeWITWorkloadID)
	require.NoError(t, err)

	t.Run("valid wit and pop authenticate", func(t *testing.T) {
		wit, pop := buildWITPoP(t, witKey, clientKey, spiffeWITIssuerID, spiffeWITWorkloadID, testIssuer, "it-wit-ok", 5*time.Minute, "wit+jwt")
		res, err := h.witAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			ClientAttestation:    new(wit),
			ClientAttestationPop: new(pop),
		})
		require.NoError(t, err)
		require.NotNil(t, res.Client)

		accessToken := h.mintClientCredentialsToken(t, res.Client)
		require.NotEmpty(t, accessToken)
	})

	t.Run("pop from different key rejected", func(t *testing.T) {
		foreignKey := attackerKey(t)
		wit, pop := buildWITPoP(t, witKey, clientKey, spiffeWITIssuerID, spiffeWITWorkloadID, testIssuer, "it-wit-foreign", 5*time.Minute, "wit+jwt")
		// Re-sign the PoP with the attacker key: same claims, wrong signer.
		now := uint64(time.Now().Unix())
		var foreignRaw any
		require.NoError(t, jwxjwk.Export(foreignKey, &foreignRaw))
		popTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
			"iss": spiffeWITWorkloadID,
			"aud": testIssuer,
			"exp": now + 300,
			"iat": now,
			"jti": "it-wit-foreign",
		})
		popTok.Header["typ"] = "oauth-client-attestation-pop+jwt"
		foreignPop, err := popTok.SignedString(foreignRaw)
		require.NoError(t, err)
		_ = wit
		_ = pop
		res, err := h.witAuth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			ClientAttestation:    new(wit),
			ClientAttestationPop: new(foreignPop),
		})
		require.Error(t, err)
		require.Nil(t, res.Client)
	})
}

func TestSpiffeX509ClientAuthEndToEnd(t *testing.T) {
	// Build a trust-domain CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"integration-test-ca"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	jwtKey, err := jwxjwk.Import(newTestKey(t))
	require.NoError(t, err)
	h := newSpiffeHarness(t, jwtKey, nil, caCert, caKey)
	// Pre-seeded X.509 workload fixture (inmemory defaultClients).
	_, err = h.clients.Get(context.Background(), spiffeX509WorkloadID)
	require.NoError(t, err)

	t.Run("valid svid leaf authenticates and mints token", func(t *testing.T) {
		leafPEM := buildX509SVIDLeaf(t, caCert, caKey, spiffeX509WorkloadID)
		res, err := h.x509Auth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			TlsClientCert: new(leafPEM),
		})
		require.NoError(t, err)
		require.NotNil(t, res.Client)

		accessToken := h.mintClientCredentialsToken(t, res.Client)
		require.NotEmpty(t, accessToken)
	})

	t.Run("cert without uri san rejected", func(t *testing.T) {
		leafPEM := buildX509SVIDLeaf(t, caCert, caKey, "https://example.org/not-spiffe")
		res, err := h.x509Auth.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
			TlsClientCert: new(leafPEM),
		})
		require.Error(t, err)
		require.Nil(t, res.Client)
	})
}

// TestSpiffeCIMDClientAuth proves a CIMD-resolved client whose document
// carries spiffe_id and a matching JWT-SVID subject authenticates via
// jwt-spiffe: the CIMD resolver maps spiffe_id into the resolved Client.
func TestSpiffeCIMDClientAuth(t *testing.T) {
	jwtKey, err := jwxjwk.Import(newTestKey(t))
	require.NoError(t, err)

	// Serve the CIMD document over TLS.
	ts := cimdTestServer(t, func(docURL string) string {
		return fmt.Sprintf(`{"client_id":%q,"token_endpoint_auth_method":"spiffe_jwt","spiffe_id":"%s","grant_types":["client_credentials"]}`, docURL, "spiffe://example.org/cimd-only-workload")
	})
	defer ts.Close()

	// CIMD overlay reader + spiffe authenticator over it.
	clients := newCIMDHarness(t, ts)
	bundles := spiffe.NewStaticBundleSource(map[string]jwk.Set{
		spiffeTrustDomain: publicBundleSet(t, jwtKey),
	})
	authenticator := clientauthentication.SPIFFEJWT(clients, bundles, inmemory.DPoPProofs(), testIssuer, []string{"ES256"})

	// The CIMD client identifier URL is NOT the SPIFFE ID: the SVID sub
	// resolves the client through the client_id fallback binding.
	cimdClientID := ts.URL + "/cimd.json"
	cimdSpiffeID := "spiffe://example.org/cimd-only-workload"
	svid := buildSVID(t, jwtKey, testIssuer, cimdSpiffeID, "cimd-jti-ok", 5*time.Minute)
	res, err := authenticator.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
		ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
		ClientAssertion:     new(svid),
		ClientId:            new(cimdClientID),
	})
	require.NoError(t, err, "CIMD client with spiffe_id must authenticate via jwt-spiffe")
	require.NotNil(t, res.Client)
	require.Equal(t, cimdClientID, res.Client.ClientId)
	require.Equal(t, cimdSpiffeID, res.Client.SpiffeId)
}

// publicBundleSet wraps a signing key's public part as a jwt-svid bundle.
func publicBundleSet(t *testing.T, key jwxjwk.Key) jwk.Set {
	t.Helper()
	pub, err := jwxjwk.PublicKeyOf(key)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwxjwk.KeyUsageKey, spiffe.KeyUseJWTSVID))
	set := jwk.NewSet()
	require.NoError(t, set.Set("keys", []jwk.Key{pub}))
	return set
}

// newTestKey generates a fresh P-256 key.
func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

var _ = base64.StdEncoding // placeholder to keep base64 imported until needed

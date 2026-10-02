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
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package httpkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

const clientAuthTestIssuer = "http://127.0.0.1:8080"

// clientAuthHarness wires the client-authentication middleware over the
// in-memory client registry, mirroring the authorization-server assembly.
// The downstream handler captures the client resolved into the request
// context.
type clientAuthHarness struct {
	server      *httptest.Server
	clients     storage.Client
	attesterKey any // raw ES256 signer for attestation fixtures
	clientPub   []byte
}

func newClientAuthHarness(t *testing.T) *clientAuthHarness {
	t.Helper()

	clients := inmemory.Clients()

	gotClientID := ""
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if client, ok := clientauthentication.FromContext(r.Context()); ok {
			gotClientID = client.ClientId
		}
		w.WriteHeader(http.StatusOK)
	})
	_ = gotClientID

	mw := ClientAuthentication(
		clients,
		clientAuthTestIssuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		inmemory.DPoPProofs(),
		profile.Strict(),
	)
	ts := httptest.NewServer(mw(inner))
	t.Cleanup(ts.Close)

	// ES256 signing fixture: a fresh P-256 key exported both as raw
	// crypto signer and public JWK JSON.
	rawKey := newP256Signer(t)
	var signer any
	require.NoError(t, jwxjwk.Export(rawKey, &signer))
	pub := newPublicJWKJSON(t, rawKey)

	return &clientAuthHarness{
		server:      ts,
		clients:     clients,
		attesterKey: signer,
		clientPub:   pub,
	}
}

// registerClient stores a client fixture and returns its assigned ID.
func (h *clientAuthHarness) registerClient(t *testing.T, c *clientv1.Client) string {
	t.Helper()

	id, err := h.clients.Register(context.Background(), c)
	require.NoError(t, err)

	return id
}

// privateKeyJWTAssertion signs a private_key_jwt client assertion bound to
// the given audience.
func (h *clientAuthHarness) privateKeyJWTAssertion(t *testing.T, clientID, audience string) string {
	t.Helper()

	now := time.Now()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": uint64(now.Unix()),
		"exp": uint64(now.Add(5 * time.Minute).Unix()),
		"jti": "httpkit-ca-" + clientID,
	})
	s, err := tok.SignedString(h.attesterKey)
	require.NoError(t, err)

	return s
}

// attestationPoP signs a Client Attestation PoP JWT (draft section 5.1)
// with the fixture key.
func (h *clientAuthHarness) attestationPoP(t *testing.T, audience, jti string) string {
	t.Helper()

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"aud": audience,
		"jti": jti,
		"iat": uint64(time.Now().Unix()),
	})
	tok.Header["typ"] = oidc.TypClientAttestationPoPJWT
	s, err := tok.SignedString(h.attesterKey)
	require.NoError(t, err)

	return s
}

// postForm sends a urlencoded token-endpoint style request and returns the
// response and parsed JSON body.
func (h *clientAuthHarness) postForm(t *testing.T, form url.Values, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	parsed := map[string]any{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &parsed)
	}

	return res, parsed
}

// requireErrorBody asserts the RFC error payload shape.
func requireErrorBody(t *testing.T, body map[string]any, wantCode string) {
	t.Helper()
	require.Equal(t, wantCode, body["error"], "body: %v", body)
}

// TestClientAuthMiddlewarePublicClientQueryParam: a query-string client_id
// resolves a public client and injects it into the downstream request
// context (RFC 6749 section 2.3.1 public client identification).
func TestClientAuthMiddlewarePublicClientQueryParam(t *testing.T) {
	h := newClientAuthHarness(t)

	publicID := h.registerClient(t, &clientv1.Client{
		ClientType: clientv1.ClientType_CLIENT_TYPE_PUBLIC,
		ClientName: "public-app",
	})

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/token?client_id="+url.QueryEscape(publicID), nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, http.StatusOK, res.StatusCode)
}

// TestClientAuthMiddlewareConfidentialClientWithoutCredentials: a
// confidential client identifier in the query string without any
// credential is rejected 401 invalid_client.
func TestClientAuthMiddlewareConfidentialClientWithoutCredentials(t *testing.T) {
	h := newClientAuthHarness(t)

	confidentialID := h.registerClient(t, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "confidential-app",
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/token?client_id="+url.QueryEscape(confidentialID), nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

// TestClientAuthMiddlewareUnknownClientQueryParam: an unregistered client
// identifier is rejected 401 invalid_client without leaking existence.
func TestClientAuthMiddlewareUnknownClientQueryParam(t *testing.T) {
	h := newClientAuthHarness(t)

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/token?client_id=unknown-client", nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

// TestClientAuthMiddlewareMalformedForm: a POST with an unparseable form
// body is a 400 invalid_request.
func TestClientAuthMiddlewareMalformedForm(t *testing.T) {
	h := newClientAuthHarness(t)

	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/token", strings.NewReader("%!"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, http.StatusBadRequest, res.StatusCode)
}

// TestClientAuthMiddlewareNoCredentials: a POST without any credential
// input maps to Select's no-method outcome: 401 invalid_request.
func TestClientAuthMiddlewareNoCredentials(t *testing.T) {
	h := newClientAuthHarness(t)

	res, body := h.postForm(t, url.Values{"grant_type": {oidc.GrantTypeClientCredentials}}, nil)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	requireErrorBody(t, body, "invalid_request")
}

// TestClientAuthMiddlewarePrivateKeyJWT: a valid private_key_jwt
// assertion authenticates the confidential client and reaches the
// downstream handler with the client in context.
func TestClientAuthMiddlewarePrivateKeyJWT(t *testing.T) {
	h := newClientAuthHarness(t)

	clientID := h.registerClient(t, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "pkjwt-app",
		Jwks:                    h.clientPub,
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})

	form := url.Values{
		"grant_type":            {oidc.GrantTypeClientCredentials},
		"client_id":             {clientID},
		"client_assertion_type": {oidc.AssertionTypeJWTBearer},
		"client_assertion":      {h.privateKeyJWTAssertion(t, clientID, clientAuthTestIssuer)},
	}
	res, body := h.postForm(t, form, nil)
	require.Equal(t, http.StatusOK, res.StatusCode, "body: %v", body)
}

// TestClientAuthMiddlewarePrivateKeyJWTBadAssertion: a tampered assertion
// is a 401 invalid_client, and the middleware does not crash on a
// non-nil error response with a payload error.
func TestClientAuthMiddlewarePrivateKeyJWTBadAssertion(t *testing.T) {
	h := newClientAuthHarness(t)

	clientID := h.registerClient(t, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "pkjwt-app",
		Jwks:                    h.clientPub,
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})

	form := url.Values{
		"grant_type":            {oidc.GrantTypeClientCredentials},
		"client_id":             {clientID},
		"client_assertion_type": {oidc.AssertionTypeJWTBearer},
		"client_assertion":      {"not-a-jwt"},
	}
	res, body := h.postForm(t, form, nil)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	requireErrorBody(t, body, "invalid_request")
}

// TestClientAuthMiddlewareStaleAttestationMapsTo400: an expired attestation
// must surface as 400 use_fresh_attestation (draft-ietf-oauth-
// attestation-based-client-auth-11 section 7.4), not as a 401 challenge —
// the middleware-specific status mapping added with the gRPC refactor.
func TestClientAuthMiddlewareStaleAttestationMapsTo400(t *testing.T) {
	h := newClientAuthHarness(t)

	attesterID := h.registerClient(t, &clientv1.Client{
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName: "attester",
		Jwks:       h.clientPub,
	})
	attestedID := h.registerClient(t, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "attested",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: oidc.AuthMethodClientAttestationJWT,
	})

	// Expired attestation JWT carrying the client public key in cnf.jwk.
	now := time.Now()
	attestation := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": attesterID,
		"sub": attestedID,
		"iat": uint64(now.Add(-10 * time.Minute).Unix()),
		"exp": uint64(now.Add(-5 * time.Minute).Unix()),
		"cnf": map[string]any{"jwk": json.RawMessage(h.clientPub)},
	})
	attestation.Header["typ"] = oidc.TypClientAttestationJWT
	attestationRaw, err := attestation.SignedString(h.attesterKey)
	require.NoError(t, err)

	form := url.Values{"grant_type": {oidc.GrantTypeClientCredentials}}
	res, body := h.postForm(t, form, map[string]string{
		"OAuth-Client-Attestation":     attestationRaw,
		"OAuth-Client-Attestation-PoP": h.attestationPoP(t, clientAuthTestIssuer, "stale-pop"),
	})

	require.Equal(t, http.StatusBadRequest, res.StatusCode, "body: %v", body)
	requireErrorBody(t, body, "use_fresh_attestation")
}

// TestClientAuthMiddlewarePemClientCertificate: a request without TLS
// state yields no PEM certificate, TLS state without peer certificates
// yields none either, and a peer leaf certificate is returned PEM-encoded
// (RFC 8705 section 2 hoisting).
func TestClientAuthMiddlewarePemClientCertificate(t *testing.T) {
	// No TLS state at all (plain HTTP request).
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	require.Empty(t, pemClientCertificate(r))

	// TLS state but no client certificate presented.
	r = httptest.NewRequest(http.MethodPost, "/token", nil)
	r.TLS = &tls.ConnectionState{}
	require.Empty(t, pemClientCertificate(r))

	// A presented leaf certificate is PEM-encoded.
	leaf := selfSignedPEMCertificate(t)
	r = httptest.NewRequest(http.MethodPost, "/token", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	require.Contains(t, pemClientCertificate(r), "BEGIN CERTIFICATE")
}

// selfSignedPEMCertificate generates a throwaway self-signed certificate
// for the PEM hoisting assertions.
func selfSignedPEMCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// newP256Signer builds a fresh P-256 signing key exported as a raw
// gojwt-compatible signer.
func newP256Signer(t *testing.T) jwxjwk.Key {
	t.Helper()

	raw, err := jwxjwk.ParseKey([]byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`))
	require.NoError(t, err)

	return raw
}

// newPublicJWKJSON renders the public part of the fixture key as a JWKS
// JSON document.
func newPublicJWKJSON(t *testing.T, key jwxjwk.Key) []byte {
	t.Helper()

	pub, err := jwxjwk.PublicKeyOf(key)
	require.NoError(t, err)

	pubJSON, err := json.Marshal(map[string]any{"keys": []any{pub}})
	require.NoError(t, err)

	return pubJSON
}

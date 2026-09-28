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

package clientauthentication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	jwxcert "github.com/lestrrat-go/jwx/v3/cert"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	storagemock "zntr.io/solid/server/storage/mock"
)

// selfSignedFixture holds a self-signed client certificate (DER + PEM) and
// the JWKS registration document that conveys it as an x5c chain
// (RFC 8705 section 2.2.2, via the RFC 7591 jwks metadata parameter).
type selfSignedFixture struct {
	certPEM  string
	certDER  []byte
	jwksJSON []byte
}

// newSelfSignedFixture builds one self-signed certificate and its JWKS
// registration. The JWK carries the certificate public key members plus
// the x5c chain, exactly as RFC 8705 section 2.2.2 requires (JWK members
// such as x and y remain present even though they are not utilized for
// the match).
func newSelfSignedFixture(t *testing.T) *selfSignedFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed-client.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	k, err := jwxjwk.Import(&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwxjwk.AlgorithmKey, "ES256"))
	require.NoError(t, k.Set(jwxjwk.KeyUsageKey, "sig"))
	chain := &jwxcert.Chain{}
	require.NoError(t, chain.Add([]byte(pemEncodeCert(t, der))))
	require.NoError(t, k.Set(jwxjwk.X509CertChainKey, chain))

	set := jwk.NewSet()
	require.NoError(t, set.Set("keys", []jwk.Key{k}))
	doc, err := json.Marshal(set)
	require.NoError(t, err)

	return &selfSignedFixture{
		certPEM:  pemEncodeCert(t, der),
		certDER:  der,
		jwksJSON: doc,
	}
}

// newForeignSelfSignedCert builds a DIFFERENT self-signed certificate (not
// registered for the client) to prove non-matching certificates fail.
func newForeignSelfSignedCert(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "attacker.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pemEncodeCert(t, der)
}

func runSelfSignedTLSClientAuth(t *testing.T, req *clientv1.AuthenticateRequest, client *clientv1.Client, expectLookup bool) (*clientv1.AuthenticateResponse, error) {
	t.Helper()

	ctrl := gomock.NewController(t)
	clients := storagemock.NewMockClientReader(ctrl)
	if expectLookup {
		clients.EXPECT().Get(gomock.Any(), req.GetClientId()).Return(client, nil)
	}

	return SelfSignedTLSClientAuth(clients).Authenticate(context.Background(), req)
}

func Test_selfSignedTLSClientAuthentication_Authenticate(t *testing.T) {
	fx := newSelfSignedFixture(t)

	t.Run("registered certificate authenticates", func(t *testing.T) {
		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &fx.certPEM,
		}
		client := &clientv1.Client{
			ClientId:                "client",
			TokenEndpointAuthMethod: oidc.AuthMethodSelfSignedTLSClientAuth,
			Jwks:                    fx.jwksJSON,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, client, true)
		require.NoError(t, err)
		require.NotNil(t, res.Client)
		assert.Equal(t, "client", res.Client.ClientId)
		assert.Nil(t, res.Error)
	})

	t.Run("unregistered certificate rejected", func(t *testing.T) {
		attackerPEM := newForeignSelfSignedCert(t)
		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &attackerPEM,
		}
		client := &clientv1.Client{
			ClientId:                "client",
			TokenEndpointAuthMethod: oidc.AuthMethodSelfSignedTLSClientAuth,
			Jwks:                    fx.jwksJSON,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, client, true)
		require.Error(t, err)
		require.Nil(t, res.Client)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})

	t.Run("no registered jwks fails closed", func(t *testing.T) {
		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &fx.certPEM,
		}
		client := &clientv1.Client{
			ClientId:                "client",
			TokenEndpointAuthMethod: oidc.AuthMethodSelfSignedTLSClientAuth,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, client, true)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})

	t.Run("malformed jwks fails closed", func(t *testing.T) {
		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &fx.certPEM,
		}
		client := &clientv1.Client{
			ClientId:                "client",
			TokenEndpointAuthMethod: oidc.AuthMethodSelfSignedTLSClientAuth,
			Jwks:                    []byte("not-a-jwks"),
		}

		res, err := runSelfSignedTLSClientAuth(t, req, client, true)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})

	t.Run("method confusion rejected", func(t *testing.T) {
		// A client registered for tls_client_auth (PKI) must not
		// authenticate via the self-signed method even with a matching
		// certificate.
		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &fx.certPEM,
		}
		client := &clientv1.Client{
			ClientId:                "client",
			TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
			Jwks:                    fx.jwksJSON,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, client, true)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})

	t.Run("missing client_id rejected", func(t *testing.T) {
		req := &clientv1.AuthenticateRequest{
			TlsClientCert: &fx.certPEM,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, nil, false)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})

	t.Run("missing certificate rejected", func(t *testing.T) {
		req := &clientv1.AuthenticateRequest{
			ClientId: strPtr("client"),
		}

		res, err := runSelfSignedTLSClientAuth(t, req, nil, false)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_request", res.Error.Err)
	})

	t.Run("expired certificate rejected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "expired.example.org"},
			NotBefore:    time.Now().Add(-2 * time.Hour),
			NotAfter:     time.Now().Add(-time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		expiredPEM := pemEncodeCert(t, der)

		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &expiredPEM,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, nil, false)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})

	t.Run("garbage pem rejected", func(t *testing.T) {
		garbage := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", "garbage!")
		req := &clientv1.AuthenticateRequest{
			ClientId:      strPtr("client"),
			TlsClientCert: &garbage,
		}

		res, err := runSelfSignedTLSClientAuth(t, req, nil, false)
		require.Error(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, "invalid_client", res.Error.Err)
	})
}

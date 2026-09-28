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

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/examples/authorizationserver/middleware"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/storage/inmemory"
)

// Live mutual-TLS coverage (RFC 8705 section 2): the whole chain from a
// REAL TLS handshake — client certificate presented during the handshake,
// r.TLS.PeerCertificates populated by the TLS stack, PEM-extracted by the
// example middleware, processed by the real tls_client_auth processor —
// through client authentication. No other test exercises the middleware
// over an actual TLS transport; this pins the presentation wiring.

// buildClientCertMaterial generates a fresh client key + self-signed
// certificate and returns (tls.Certificate, parsed cert).
func buildClientCertMaterial(t *testing.T, commonName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(cryptoRand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return pair, parsed
}

// newLiveMTLSServer boots a TLS server requiring client certificates and
// wrapping the real example ClientAuthentication middleware over a
// 200-returning handler. The registered client must be registered in the
// middleware's own client store.
func newLiveMTLSServer(t *testing.T, client *clientv1.Client) (baseURL string, closeFn func(), registeredID string) {
	t.Helper()

	clients := inmemory.Clients()
	registeredID, err := clients.Register(context.Background(), client)
	if err != nil {
		t.Fatalf("unable to register client: %v", err)
	}

	srv := httptest.NewUnstartedServer(middleware.ClientAuthentication(
		clients,
		"https://as.example.org",
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	// RFC 8705 section 2: the client certificate is presented during the
	// TLS handshake. RequireAnyClientCert forces its presentation; chain
	// validation is a deployment concern (section 6.1) and is not
	// performed here, mirroring the self-signed posture.
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()

	return srv.URL, srv.Close, registeredID
}

// mtlsClient builds an HTTP client presenting the given certificate over
// the loopback TLS server.
func mtlsClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				//nolint:gosec // loopback test server with generated self-signed server cert
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}
}

// TestRFC8705_LiveMTLSHandshakeToAuthentication drives the full chain over
// a real TLS socket: handshake with client certificate ->
// r.TLS.PeerCertificates -> PEM extraction by the example middleware ->
// TLSClientAuth subject binding -> 200. The negative control proves the
// same wiring rejects a different certificate (no binding bypass at the
// presentation layer).
func TestRFC8705_LiveMTLSHandshakeToAuthentication(t *testing.T) {
	pair, parsed := buildClientCertMaterial(t, "live-mtls-client.example.org")

	// A client registered for tls_client_auth with a subject_dn binding
	// matching the certificate (RFC 8705 section 2.1.2).
	client := &clientv1.Client{
		ClientId:                "live-mtls-client",
		ClientName:              "live-mtls-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		RedirectUris:            []string{testRedirectURI},
		TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
		TlsClientAuthSubjectDn:  parsed.Subject.String(),
	}

	baseURL, closeFn, registeredID := newLiveMTLSServer(t, client)
	defer closeFn()

	// The middleware resolves the client from the client_id form
	// parameter (RFC 8705 section 2: client_id is REQUIRED on mutual-TLS
	// requests); the value is the id assigned by the client store.
	form := func() string { return "client_id=" + registeredID }

	t.Run("handshake with matching certificate authenticates", func(t *testing.T) {
		resp, err := mtlsClient(pair).Post(baseURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form()))
		require.NoError(t, err, "the TLS handshake and request must complete")
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, "the registered client certificate must authenticate through the full middleware chain")
	})

	t.Run("handshake with different certificate rejected", func(t *testing.T) {
		attackerPair, _ := buildClientCertMaterial(t, "attacker.example.org")

		resp, err := mtlsClient(attackerPair).Post(baseURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form()))
		require.NoError(t, err, "the handshake still completes (any client cert accepted at the TLS layer)")
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "an unregistered certificate must be rejected by the subject binding")
	})
}

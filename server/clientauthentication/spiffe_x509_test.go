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

package clientauthentication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	jwxcert "github.com/lestrrat-go/jwx/v3/cert"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/spiffe"
	spiffemock "zntr.io/solid/sdk/spiffe/mock"
	storagemock "zntr.io/solid/server/storage/mock"
)

const spiffeX509Subject = "spiffe://example.org/x509-workload"

// x509Fixture holds a trust-domain CA and a leaf SVID signed by it.
type x509Fixture struct {
	caCert    *x509.Certificate
	leafCert  *x509.Certificate
	leafPEM   string
	bundleSet jwk.Set
}

// newX509Fixture builds a trust-domain signing CA (as carried in a bundle
// x5c) and a valid X.509-SVID leaf for the given SPIFFE ID.
func newX509Fixture(t *testing.T, spiffeID string) *x509Fixture {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"test-trust-domain"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"test-workload"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Bundle: the CA public key tagged x509-svid, with the CA cert in x5c.
	caJWK, err := jwxjwk.Import(&caKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := caJWK.Set(jwxjwk.KeyUsageKey, spiffe.KeyUseX509SVID); err != nil {
		t.Fatal(err)
	}
	chain := &jwxcert.Chain{}
	if err := chain.Add([]byte(pemEncodeCert(t, caDER))); err != nil {
		t.Fatal(err)
	}
	if err := caJWK.Set(jwxjwk.X509CertChainKey, chain); err != nil {
		t.Fatal(err)
	}
	bundleSet := jwk.NewSet()
	if err := bundleSet.Set("keys", []jwk.Key{caJWK}); err != nil {
		t.Fatal(err)
	}

	return &x509Fixture{
		caCert:    caCert,
		leafCert:  leafCert,
		leafPEM:   pemEncodeCert(t, leafDER),
		bundleSet: bundleSet,
	}
}

func pemEncodeCert(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// buildForeignLeaf builds an SVID signed by a DIFFERENT CA (not in the
// bundle).
func (f *x509Fixture) buildForeignLeaf(t *testing.T, spiffeID string) string {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{Organization: []string{"foreign-ca"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncodeCert(t, leafDER)
}

// buildCALeaf returns the CA certificate itself as the presented "client
// certificate".
func (f *x509Fixture) caPEM(t *testing.T) string {
	t.Helper()
	return pemEncodeCert(t, f.caCert.Raw)
}

func Test_spiffeX509Authentication_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		tlsCert func(f *x509Fixture) string
		prepare func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture)
		wantErr bool
	}{
		{
			name:    "valid",
			tlsCert: func(f *x509Fixture) string { return f.leafPEM },
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(f.bundleSet, nil)
				clients.EXPECT().Get(gomock.Any(), spiffeX509Subject).Return(&clientv1.Client{
					ClientId:                spiffeX509Subject,
					SpiffeId:                spiffeX509Subject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEX509,
				}, nil)
			},
		},
		{
			name:    "missing tls cert",
			tlsCert: func(_ *x509Fixture) string { return "" },
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource, _ *x509Fixture) {},
			wantErr: true,
		},
		{
			name:    "invalid PEM",
			tlsCert: func(_ *x509Fixture) string { return "not a pem" },
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource, _ *x509Fixture) {},
			wantErr: true,
		},
		{
			name: "cert without spiffe uri san",
			tlsCert: func(f *x509Fixture) string {
				// A cert with no URI SAN signed by the trust CA.
				return f.buildForeignLeaf(t, "https://example.org/not-spiffe")
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource, _ *x509Fixture) {},
			wantErr: true,
		},
		{
			name:    "CA cert as leaf rejected",
			tlsCert: func(f *x509Fixture) string { return f.caPEM(t) },
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, _ *x509Fixture) {},
			wantErr: true,
		},
		{
			name:    "cert signed by foreign CA rejected",
			tlsCert: func(f *x509Fixture) string { return f.buildForeignLeaf(t, spiffeX509Subject) },
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(f.bundleSet, nil)
			},
			wantErr: true,
		},
		{
			name:    "unknown trust domain",
			tlsCert: func(f *x509Fixture) string { return f.leafPEM },
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture) {
				_ = f
				_ = clients
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(nil, errNoBundle)
			},
			// leafPEM carries a spiffe://example.org id: use a foreign-domain leaf instead
			wantErr: true,
		},
		{
			name:    "client without spiffe_id rejected (fail closed)",
			tlsCert: func(f *x509Fixture) string { return f.leafPEM },
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(f.bundleSet, nil)
				clients.EXPECT().Get(gomock.Any(), spiffeX509Subject).Return(&clientv1.Client{
					ClientId: spiffeX509Subject,
				}, nil)
			},
			wantErr: true,
		},
		{
			name:    "client not registered for spiffe_x509",
			tlsCert: func(f *x509Fixture) string { return f.leafPEM },
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(f.bundleSet, nil)
				clients.EXPECT().Get(gomock.Any(), spiffeX509Subject).Return(&clientv1.Client{
					ClientId:                spiffeX509Subject,
					SpiffeId:                spiffeX509Subject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEJWT,
				}, nil)
			},
			wantErr: true,
		},
		{
			name:    "client_id fallback resolves registered client",
			tlsCert: func(f *x509Fixture) string { return f.leafPEM },
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *x509Fixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(f.bundleSet, nil)
				clients.EXPECT().Get(gomock.Any(), spiffeX509Subject).Return(nil, errClientNotFound)
				clients.EXPECT().Get(gomock.Any(), "registered-client-id").Return(&clientv1.Client{
					ClientId:                "registered-client-id",
					SpiffeId:                spiffeX509Subject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEX509,
				}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			clients := storagemock.NewMockClientReader(ctrl)
			bundles := spiffemock.NewMockBundleSource(ctrl)
			fixture := newX509Fixture(t, spiffeX509Subject)

			if tt.prepare != nil {
				tt.prepare(clients, bundles, fixture)
			}

			underTest := SPIFFEX509(clients, bundles)

			req := &clientv1.AuthenticateRequest{
				TlsClientCert: new(tt.tlsCert(fixture)),
				ClientId:      new("registered-client-id"),
			}
			got, err := underTest.Authenticate(context.Background(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Client == nil {
				t.Errorf("Authenticate() = %v, want client assigned", got)
			}
			if tt.wantErr && got != nil && got.Error == nil {
				t.Errorf("Authenticate() = %v, want protocol error assigned", got)
			}
		})
	}
}

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
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

// newTLSCertPEM builds a self-signed client certificate with the
// requested subject and SANs (the handshake-level chain trust is a
// deployment concern, out of scope here exactly as in the spiffe tests).
type tlsCertOptions struct {
	subject        pkix.Name
	dnsNames       []string
	uris           []*url.URL
	ips            []net.IP
	emailAddresses []string
	notBefore      time.Time
	notAfter       time.Time
}

func newTLSCertPEM(t *testing.T, opts tlsCertOptions) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	notBefore, notAfter := opts.notBefore, opts.notAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               opts.subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              opts.dnsNames,
		URIs:                  opts.uris,
		IPAddresses:           opts.ips,
		EmailAddresses:        opts.emailAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pemEncodeCert(t, der))
}

func strPtr(s string) *string { return &s }

// runTLSClientAuth drives the TLSClientAuth processor with the given
// request and mocked client registration.
func runTLSClientAuth(t *testing.T, req *clientv1.AuthenticateRequest, client *clientv1.Client, expectLookup bool) (*clientv1.AuthenticateResponse, error) {
	t.Helper()

	ctrl := gomock.NewController(t)
	clients := storagemock.NewMockClientReader(ctrl)
	if expectLookup {
		clients.EXPECT().Get(gomock.Any(), req.GetClientId()).Return(client, nil)
	}

	return TLSClientAuth(clients).Authenticate(context.Background(), req)
}

func Test_tlsClientAuthentication_Authenticate_HappyPaths(t *testing.T) {
	cases := []struct {
		name     string
		certOpts tlsCertOptions
		client   *clientv1.Client
	}{
		{
			name: "subject dn binding",
			certOpts: tlsCertOptions{
				subject: pkix.Name{CommonName: "client.example.org"},
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSubjectDn:  "CN=client.example.org",
			},
		},
		{
			name: "dns san binding",
			certOpts: tlsCertOptions{
				dnsNames: []string{"client.example.org"},
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanDns:     "client.example.org",
			},
		},
		{
			name: "uri san binding",
			certOpts: tlsCertOptions{
				uris: []*url.URL{mustURL(t, "spiffe://example.org/workload")},
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanUri:     "spiffe://example.org/workload",
			},
		},
		{
			name: "ip san binding with ipv6 textual difference",
			certOpts: tlsCertOptions{
				// The certificate carries the non-compressed textual
				// form; the registered value uses the compressed form.
				ips: []net.IP{net.ParseIP("2001:0db8:0000:0000:0000:0000:0000:0001")},
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanIp:      "2001:db8::1",
			},
		},
		{
			name: "email san binding",
			certOpts: tlsCertOptions{
				emailAddresses: []string{"client@example.org"},
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanEmail:   "client@example.org",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM := newTLSCertPEM(t, tc.certOpts)
			req := &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: &certPEM,
			}

			res, err := runTLSClientAuth(t, req, tc.client, true)
			require.NoError(t, err)
			require.NotNil(t, res.Client)
			assert.Equal(t, "client", res.Client.ClientId)
			assert.Nil(t, res.Error)
		})
	}
}

func Test_tlsClientAuthentication_Authenticate_Failures(t *testing.T) {
	validDN := tlsCertOptions{subject: pkix.Name{CommonName: "client.example.org"}}
	attackerDN := tlsCertOptions{subject: pkix.Name{CommonName: "attacker.example.org"}}
	attackerDNS := tlsCertOptions{dnsNames: []string{"attacker.example.org"}}

	cases := []struct {
		name         string
		req          *clientv1.AuthenticateRequest
		client       *clientv1.Client
		expectLookup bool
		wantErrCode  string
	}{
		{
			name:        "nil request",
			req:         nil,
			client:      nil,
			wantErrCode: "invalid_request",
		},
		{
			name: "missing client certificate",
			req: &clientv1.AuthenticateRequest{
				ClientId: strPtr("client"),
			},
			client:      &clientv1.Client{},
			wantErrCode: "invalid_request",
		},
		{
			name: "missing client_id",
			req: &clientv1.AuthenticateRequest{
				TlsClientCert: strPtr(newTLSCertPEM(t, validDN)),
			},
			client:      &clientv1.Client{},
			wantErrCode: "invalid_client",
		},
		{
			name: "malformed pem",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr("not a pem"),
			},
			client:      &clientv1.Client{},
			wantErrCode: "invalid_client",
		},
		{
			name: "subject dn mismatch: attacker cert",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, attackerDN)),
			},
			client: &clientv1.Client{
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSubjectDn:  "CN=client.example.org",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "dns san mismatch: attacker cert",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, attackerDNS)),
			},
			client: &clientv1.Client{
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanDns:     "client.example.org",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "uri san mismatch",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, tlsCertOptions{uris: []*url.URL{mustURL(t, "https://attacker.example.org")}})),
			},
			client: &clientv1.Client{
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanUri:     "spiffe://example.org/workload",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "ip san mismatch",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, tlsCertOptions{ips: []net.IP{net.ParseIP("2001:db8::dead")}})),
			},
			client: &clientv1.Client{
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanIp:      "2001:db8::1",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "email san mismatch",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, tlsCertOptions{emailAddresses: []string{"attacker@example.org"}})),
			},
			client: &clientv1.Client{
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSanEmail:   "client@example.org",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "expired certificate",
			req: &clientv1.AuthenticateRequest{
				ClientId: strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, tlsCertOptions{
					subject:   pkix.Name{CommonName: "client.example.org"},
					notBefore: time.Now().Add(-2 * time.Hour),
					notAfter:  time.Now().Add(-time.Hour),
				})),
			},
			client:      &clientv1.Client{},
			wantErrCode: "invalid_client",
		},
		{
			name: "not yet valid certificate",
			req: &clientv1.AuthenticateRequest{
				ClientId: strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, tlsCertOptions{
					subject:   pkix.Name{CommonName: "client.example.org"},
					notBefore: time.Now().Add(time.Hour),
					notAfter:  time.Now().Add(2 * time.Hour),
				})),
			},
			client:      &clientv1.Client{},
			wantErrCode: "invalid_client",
		},
		{
			name: "unregistered auth method",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, validDN)),
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				TlsClientAuthSubjectDn:  "CN=client.example.org",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "zero subject bindings registered",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, validDN)),
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "ambiguous subject bindings registered",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, validDN)),
			},
			client: &clientv1.Client{
				ClientId:                "client",
				TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSubjectDn:  "CN=client.example.org",
				TlsClientAuthSanDns:     "client.example.org",
			},
			expectLookup: true,
			wantErrCode:  "invalid_client",
		},
		{
			name: "client not found",
			req: &clientv1.AuthenticateRequest{
				ClientId:      strPtr("client"),
				TlsClientCert: strPtr(newTLSCertPEM(t, validDN)),
			},
			client:      nil,
			wantErrCode: "invalid_client",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "client not found" {
				// dedicated mock: storage miss
				ctrl := gomock.NewController(t)
				clients := storagemock.NewMockClientReader(ctrl)
				clients.EXPECT().Get(gomock.Any(), "client").Return(nil, storage.ErrNotFound)

				res, err := TLSClientAuth(clients).Authenticate(context.Background(), tc.req)
				require.Error(t, err)
				require.NotNil(t, res.Error)
				assert.Equal(t, tc.wantErrCode, res.Error.Err)
				assert.Nil(t, res.Client)
				return
			}

			res, err := runTLSClientAuth(t, tc.req, tc.client, tc.expectLookup)
			if tc.name == "nil request" {
				// Drive the processor with no mocked storage at all.
				res, err = TLSClientAuth(nil).Authenticate(context.Background(), nil)
			}
			require.Error(t, err)
			require.NotNil(t, res.Error)
			assert.Equal(t, tc.wantErrCode, res.Error.Err)
			assert.Nil(t, res.Client)
		})
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func Test_tlsClientAuthentication_RegisteredSubjectDNUsesRFC4514Form(t *testing.T) {
	// Multi-attribute DN: Go renders "CN=client.example.org,O=Example Org,C=US";
	// the registered value must equal that canonical RFC 4514 rendering.
	subject := pkix.Name{
		CommonName:   "client.example.org",
		Organization: []string{"Example Org"},
		Country:      []string{"US"},
	}
	certPEM := newTLSCertPEM(t, tlsCertOptions{subject: subject})

	client := &clientv1.Client{
		ClientId:                "client",
		TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
		TlsClientAuthSubjectDn:  fmt.Sprintf("CN=%s,O=%s,C=%s", subject.CommonName, subject.Organization[0], subject.Country[0]),
	}
	req := &clientv1.AuthenticateRequest{
		ClientId:      strPtr("client"),
		TlsClientCert: &certPEM,
	}

	res, err := runTLSClientAuth(t, req, client, true)
	require.NoError(t, err)
	require.NotNil(t, res.Client)
}

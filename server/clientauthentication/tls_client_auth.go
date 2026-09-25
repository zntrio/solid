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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

// TLSClientAuth authenticates clients with the PKI mutual-TLS method
// (RFC 8705, section 2.1): the presentation layer extracts the client
// certificate from the TLS handshake, PEM-encodes it as the
// tls_client_cert request input. The TLS handshake proves possession
// of the private key and (deployment-configured) chain validation; this
// processor enforces the RFC 8705 subject binding between the
// certificate and the client's registered metadata.
//
// Chain validation is a TLS-stack/deployment concern (RFC 8705 section
// 6.1): the presentation layer decides whether the presented
// certificate was validated against the deployment's root pool. Unlike
// spiffe_x509, no trust anchors exist in the domain model here, so
// this processor MUST NOT re-validate the certificate chain.
func TLSClientAuth(clients storage.ClientReader) AuthenticationProcessor {
	return &tlsClientAuthentication{
		clients: clients,
	}
}

// -----------------------------------------------------------------------------

type tlsClientAuthentication struct {
	clients storage.ClientReader
}

//nolint:funlen,gocyclo // linear RFC-ordered validation chain; each guard is a protocol requirement
func (p *tlsClientAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate required fields for this authentication method
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}
	if req.TlsClientCert == nil || *req.TlsClientCert == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("tls_client_cert must be defined")
	}

	// RFC 8705 section 2: client_id is REQUIRED on every
	// mutual-TLS client-authenticated request so the AS can locate the
	// expected subject binding.
	if req.ClientId == nil || *req.ClientId == "" {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client_id must be defined for %s", oidc.AuthMethodTLSClientAuth)
	}

	// Decode the PEM block and parse the certificate.
	block, _ := pem.Decode([]byte(*req.TlsClientCert))
	if block == nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to decode PEM client certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to parse client certificate: %w", err)
	}

	// Validity window.
	now := time.Now()
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate is not valid at present time")
	}

	// Resolve the client.
	client, err := p.clients.Get(ctx, *req.ClientId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("error during client retrieval: %w", err)
		}
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client not found")
	}

	// Defensive: the client must be registered for the tls_client_auth method.
	if client.TokenEndpointAuthMethod != oidc.AuthMethodTLSClientAuth {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client is not registered for %s", oidc.AuthMethodTLSClientAuth)
	}

	// RFC 8705 section 2.1.2: exactly one subject binding metadata value
	// MUST be registered; zero or several is a client registration error.
	bindings := 0
	if client.TlsClientAuthSubjectDn != "" {
		bindings++
	}
	if client.TlsClientAuthSanDns != "" {
		bindings++
	}
	if client.TlsClientAuthSanUri != "" {
		bindings++
	}
	if client.TlsClientAuthSanIp != "" {
		bindings++
	}
	if client.TlsClientAuthSanEmail != "" {
		bindings++
	}
	if bindings != 1 {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client must register exactly one tls_client_auth subject")
	}

	// RFC 8705 section 2.1.2: enforce the subject binding between the
	// presented certificate and the registered metadata value.
	bound := false
	switch {
	case client.TlsClientAuthSubjectDn != "":
		// The registered value is an RFC 4514 string; pkix.Name.String()
		// renders the RFC 4514 form, so a constant-time comparison against
		// the canonical Go rendering is the predictable normalization.
		bound = types.SecureCompareString(client.TlsClientAuthSubjectDn, cert.Subject.String())
	case client.TlsClientAuthSanDns != "":
		bound = types.StringArray(cert.DNSNames).Contains(client.TlsClientAuthSanDns)
	case client.TlsClientAuthSanUri != "":
		for _, u := range cert.URIs {
			if u != nil && u.String() == client.TlsClientAuthSanUri {
				bound = true
				break
			}
		}
	case client.TlsClientAuthSanIp != "":
		registeredIP := net.ParseIP(client.TlsClientAuthSanIp)
		for _, ip := range cert.IPAddresses {
			// RFC 8705 section 2.1.2: IP comparison in binary format;
			// net.IP.Equal does exactly this.
			if registeredIP != nil && ip.Equal(registeredIP) {
				bound = true
				break
			}
		}
	case client.TlsClientAuthSanEmail != "":
		bound = types.StringArray(cert.EmailAddresses).Contains(client.TlsClientAuthSanEmail)
	}
	if !bound {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate subject does not match the registered binding")
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}

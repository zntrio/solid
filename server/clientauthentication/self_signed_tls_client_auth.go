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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
)

// SelfSignedTLSClientAuth authenticates clients with the self-signed
// certificate mutual-TLS method (RFC 8705, section 2.2): the client
// registers its X.509 certificates as `x5c` members of JWKs in its
// registered `jwks` metadata (section 2.2.2, via RFC 7591). During
// authentication, the TLS handshake validates possession of the private
// key; the processor authenticates the client when the presented
// certificate matches one of the registered certificates. Unlike the PKI
// method (section 2.1), the certificate chain is NOT validated (section
// 2.2), so this processor MUST NOT re-validate chains either.
//
// The presentation layer extracts the client certificate from the TLS
// handshake and PEM-encodes it as the tls_client_cert request input,
// exactly as for the PKI method.
func SelfSignedTLSClientAuth(clients storage.ClientReader) AuthenticationProcessor {
	return &selfSignedTLSClientAuthentication{
		clients: clients,
	}
}

// -----------------------------------------------------------------------------

type selfSignedTLSClientAuthentication struct {
	clients storage.ClientReader
}

//nolint:gocyclo // linear RFC-ordered validation chain; each guard is a protocol requirement
func (p *selfSignedTLSClientAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}
	// Validate required fields for this authentication method.
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}
	if req.TlsClientCert == nil || *req.TlsClientCert == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("tls_client_cert must be defined")
	}

	// RFC 8705 section 2: client_id is REQUIRED on every mutual-TLS
	// client-authenticated request so the AS can locate the registered
	// certificate set.
	if req.ClientId == nil || *req.ClientId == "" {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client_id must be defined for %s", oidc.AuthMethodSelfSignedTLSClientAuth)
	}

	// Decode the PEM block and parse the presented certificate.
	block, _ := pem.Decode([]byte(*req.TlsClientCert))
	if block == nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to decode PEM client certificate")
	}
	presented, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to parse client certificate: %w", err)
	}

	// Validity window of the presented certificate (a self-signed cert is
	// still an X.509 certificate with a validity period).
	now := time.Now()
	if now.After(presented.NotAfter) || now.Before(presented.NotBefore) {
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

	// Defensive: the client must be registered for the
	// self_signed_tls_client_auth method (section 2.2.1).
	if client.TokenEndpointAuthMethod != oidc.AuthMethodSelfSignedTLSClientAuth {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client is not registered for %s", oidc.AuthMethodSelfSignedTLSClientAuth)
	}

	// RFC 8705 section 2.2.2: the certificates are conveyed in the jwks
	// registration metadata parameter, each certificate represented with
	// the x5c parameter of an individual JWK. An absent jwks fails
	// closed: no registered certificate means no possible match.
	if len(client.Jwks) == 0 {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client has no registered jwks for %s", oidc.AuthMethodSelfSignedTLSClientAuth)
	}
	registered, err := jwk.Parse(client.Jwks)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to parse client registered jwks: %w", err)
	}
	if !jwksContainsCertificate(registered, presented.Raw) {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate does not match any registered certificate")
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}

// jwksContainsCertificate reports whether any JWK in the set carries the
// given DER certificate as the leaf of its x5c chain (RFC 8705 section
// 2.2.2). The match is exact DER byte equality: a certificate is a
// self-contained signed object, so byte equality is the strictest
// possible comparison — no normalization, no partial match.
func jwksContainsCertificate(set jwk.Set, der []byte) bool {
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		chain, hasChain := key.X509CertChain()
		if !hasChain || chain == nil || chain.Len() == 0 {
			continue
		}
		// The certificate is the first entry of the x5c parameter (the
		// key's own leaf). cert.Chain stores x5c entries as base64(DER).
		enc, hasLeaf := chain.Get(0)
		if !hasLeaf {
			continue
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
		n, err := base64.StdEncoding.Decode(decoded, enc)
		if err != nil {
			continue
		}
		if bytes.Equal(decoded[:n], der) {
			return true
		}
	}
	return false
}

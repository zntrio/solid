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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/storage"
)

// SPIFFEX509 authenticates clients with an X.509-SVID presented through
// mutual TLS (draft-ietf-oauth-spiffe-client-auth-02, section 3.2): the
// presentation layer extracts the client certificate, PEM-encodes it and
// carries it as the tls_client_cert request input. The TLS handshake itself
// is the freshness proof — no jti replay bookkeeping applies.
func SPIFFEX509(clients storage.ClientReader, bundles spiffe.BundleSource) AuthenticationProcessor {
	return &spiffeX509Authentication{
		clients: clients,
		bundles: bundles,
	}
}

type spiffeX509Authentication struct {
	clients storage.ClientReader
	bundles spiffe.BundleSource
}

//nolint:funlen,gocyclo // to refactor
func (p *spiffeX509Authentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
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

	// Rule 2: exactly one URI SAN carrying a valid SPIFFE ID.
	spiffeID, ok := spiffe.TrustDomainFromX509SVID(cert)
	if !ok {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate has no unique spiffe uri san")
	}

	// Rules 3-4: the SVID leaf MUST be a CA=FALSE signing certificate.
	if cert.BasicConstraintsValid && cert.IsCA {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate must not be a CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate must allow digital signature")
	}

	// Validity window.
	now := time.Now()
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate is not valid at present time")
	}

	// Rule 1: path validation against the trust domain roots carried by the
	// SPIFFE bundle (x509-svid keys, signing cert in x5c).
	trustDomain, err := spiffe.TrustDomainFromSPIFFEID(spiffeID)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("invalid spiffe id: %w", err)
	}
	bundle, err := p.bundles.Get(ctx, trustDomain)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("no bundle for trust domain %q", trustDomain)
	}
	x509SVIDKeys, err := spiffe.KeysByUse(bundle, spiffe.KeyUseX509SVID)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to filter bundle keys: %w", err)
	}
	roots, err := x509SVIDRoots(x509SVIDKeys)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to build trust roots: %w", err)
	}
	if _, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client certificate path validation failed: %w", err)
	}

	// Rule 5: client association — resolve by SPIFFE ID first, then by the
	// request client_id.
	client, err := p.clients.Get(ctx, spiffeID)
	if err != nil {
		if req.ClientId != nil && *req.ClientId != "" {
			client, err = p.clients.Get(ctx, *req.ClientId)
		}
		if err != nil {
			if !errors.Is(err, storage.ErrNotFound) {
				res.Error = rfcerrors.ServerError().Build()
				return res, fmt.Errorf("error during client retrieval: %w", err)
			}
			res.Error = rfcerrors.InvalidClient().Build()
			return res, fmt.Errorf("client not found")
		}
	}

	// Enforce the SPIFFE ID binding (draft section 5.1), fail closed.
	if client.SpiffeId == "" || !spiffe.MatchSPIFFEID(client.SpiffeId, spiffeID) {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client spiffe_id %q does not match svid spiffe id %q", client.SpiffeId, spiffeID)
	}

	// Defensive: the client must be registered for the spiffe_x509 method.
	if client.TokenEndpointAuthMethod != oidc.AuthMethodSPIFFEX509 {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client is not registered for %s", oidc.AuthMethodSPIFFEX509)
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}

// x509SVIDRoots materializes the X.509 trust anchors carried by the
// x509-svid entries of a SPIFFE bundle: every x5c chain's first certificate
// is the signing (CA) certificate of the trust domain.
func x509SVIDRoots(set jwk.Set) (*x509.CertPool, error) {
	if set == nil {
		return nil, fmt.Errorf("nil keyset")
	}
	pool := x509.NewCertPool()
	found := 0
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			continue
		}
		chain, ok := k.X509CertChain()
		if !ok {
			continue
		}
		for j := 0; j < chain.Len(); j++ {
			enc, ok := chain.Get(j)
			if !ok {
				continue
			}
			// cert.Chain stores x5c entries as base64(DER).
			der := make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
			n, err := base64.StdEncoding.Decode(der, enc)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(der[:n])
			if err != nil {
				continue
			}
			pool.AddCert(cert)
			found++
		}
	}
	if found == 0 {
		return nil, fmt.Errorf("no x509-svid trust anchor in bundle")
	}
	return pool, nil
}

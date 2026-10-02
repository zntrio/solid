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

	gojwt "github.com/golang-jwt/jwt/v5"

	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/storage"
)

// ProcessorSet aggregates the supported client-authentication processors
// and resolves which one applies to a request's credential inputs. It is
// presentation-agnostic: HTTP, gRPC or any other transport feeds it the
// same credential surface extracted from its own request encoding.
type ProcessorSet struct {
	PrivateKeyJWT     AuthenticationProcessor
	ClientAttestation AuthenticationProcessor
	SPIFFEJWT         AuthenticationProcessor
	SPIFFEWIT         AuthenticationProcessor
	SPIFFEX509        AuthenticationProcessor
	TLSClientAuth     AuthenticationProcessor
}

// NewProcessorSet builds the processor set from the shared server
// dependencies. The issuer value MUST be the authorization server's issuer
// identifier; supportedAlgorithms the accepted client-assertion signature
// algorithms; spiffeBundles the trust-domain signing-key source for the
// SPIFFE methods (draft-ietf-oauth-spiffe-client-auth-02); dpopProofs the
// shared DPoP proof (jti) store used by the proof-of-possession processors.
func NewProcessorSet(clients storage.ClientReader, issuer string,
	supportedAlgorithms []string, spiffeBundles spiffe.BundleSource,
	dpopProofs storage.DPoP,
) ProcessorSet {
	return ProcessorSet{
		PrivateKeyJWT:     PrivateKeyJWT(clients, dpopProofs, issuer, supportedAlgorithms),
		ClientAttestation: ClientAttestation(clients, dpopProofs, issuer, supportedAlgorithms),
		SPIFFEJWT:         SPIFFEJWT(clients, spiffeBundles, dpopProofs, issuer, supportedAlgorithms),
		SPIFFEWIT:         SPIFFEWIT(clients, spiffeBundles, dpopProofs, issuer, supportedAlgorithms),
		SPIFFEX509:        SPIFFEX509(clients, spiffeBundles),
		TLSClientAuth:     TLSClientAuth(clients),
	}
}

// Select resolves the applicable processor and its token-endpoint
// authentication method identifier from the credential inputs (RFC 8705
// section 2.1, draft-ietf-oauth-spiffe-client-auth-02 sections 3.2/3.3).
// ok=false when no method applies.
func (p *ProcessorSet) Select(ctx context.Context, clients storage.ClientReader,
	authMethod, attestation, attestationPop, tlsClientCertPEM, clientIDParam string,
) (AuthenticationProcessor, string, bool) {
	switch {
	case authMethod == oidc.AssertionTypeJWTSPIFFE:
		return p.SPIFFEJWT, oidc.AuthMethodSPIFFEJWT, true
	case authMethod == "" && attestation != "" && attestationPop != "":
		// draft-ietf-oauth-attestation-based-client-auth-11 section 4 vs
		// draft-ietf-oauth-spiffe-client-auth-02 section 3.3: both mechanisms
		// ride the OAuth-Client-Attestation header pair; the attestation typ
		// header parameter selects the processor.
		typ := ""
		if t, _, err := gojwt.NewParser().ParseUnverified(attestation, gojwt.MapClaims{}); err == nil {
			typ, _ = t.Header["typ"].(string)
		}
		if typ == "wit+jwt" {
			return p.SPIFFEWIT, oidc.AuthMethodSPIFFEWIT, true
		}
		return p.ClientAttestation, oidc.AuthMethodClientAttestationJWT, true
	case authMethod == "" && tlsClientCertPEM != "":
		// RFC 8705 section 2.1 takes precedence when the resolved
		// client is registered for tls_client_auth; otherwise the
		// certificate is an X.509-SVID candidate (SPIFFE draft
		// section 3.2).
		if clientIDParam != "" {
			if registered, err := clients.Get(ctx, clientIDParam); err == nil &&
				registered.TokenEndpointAuthMethod == oidc.AuthMethodTLSClientAuth {
				return p.TLSClientAuth, oidc.AuthMethodTLSClientAuth, true
			}
		}
		return p.SPIFFEX509, oidc.AuthMethodSPIFFEX509, true
	case authMethod == oidc.AssertionTypeJWTBearer:
		return p.PrivateKeyJWT, oidc.AuthMethodPrivateKeyJWT, true
	default:
		return nil, "", false
	}
}

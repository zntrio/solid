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

package main

import (
	"fmt"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/oidc"
)

// mldsaAlg is the signature algorithm advertised by this example server.
const mldsaAlg = "ML-DSA-65"

// metadataDocument builds the RFC 8414 metadata document this example
// authorization server advertises.
func metadataDocument(issuer string) *discoveryv1.ServerMetadata {
	// Prepare metadata
	md := &discoveryv1.ServerMetadata{
		Issuer:  issuer,
		JwksUri: fmt.Sprintf("%s/keys", issuer),
		SubjectTypesSupported: []string{
			oidc.SubjectTypePairwise,
		},
		AuthorizationEndpoint: fmt.Sprintf("%s/authorize", issuer),
		ResponseTypesSupported: []string{
			oidc.ResponseTypeCode,
		},
		ResponseModesSupported: []string{
			oidc.ResponseModeQuery,
			oidc.ResponseModeFragment,
			oidc.ResponseModeFormPost,
			oidc.ResponseModeQueryJWT,
			oidc.ResponseModeFragmentJWT,
			oidc.ResponseModeFormPOSTJWT,
			oidc.ResponseModeJWT,
		},
		GrantTypesSupported: []string{
			oidc.GrantTypeClientCredentials,
			oidc.GrantTypeAuthorizationCode,
			oidc.GrantTypeRefreshToken,
			oidc.GrantTypeDeviceCode,
			oidc.GrantTypeCIBA,
			oidc.GrantTypeTokenExchange,
		},
		TokenEndpoint: fmt.Sprintf("%s/token", issuer),
		TokenEndpointAuthMethodsSupported: []string{
			oidc.AuthMethodPrivateKeyJWT,
			oidc.AuthMethodClientAttestationJWT,
			oidc.AuthMethodSPIFFEJWT,
			oidc.AuthMethodSPIFFEWIT,
			oidc.AuthMethodSPIFFEX509,
			oidc.AuthMethodTLSClientAuth,
		},
		TokenEndpointAuthSigningAlgValuesSupported:             []string{mldsaAlg},
		CodeChallengeMethodsSupported:                          []string{"S256"},
		IntrospectionEndpoint:                                  fmt.Sprintf("%s/token/introspect", issuer),
		IntrospectionEndpointAuthMethodsSupported:              []string{oidc.AuthMethodPrivateKeyJWT, oidc.AuthMethodClientAttestationJWT, oidc.AuthMethodSPIFFEJWT, oidc.AuthMethodSPIFFEWIT, oidc.AuthMethodSPIFFEX509, oidc.AuthMethodTLSClientAuth},
		IntrospectionEndpointAuthSigningAlgValuesSupported:     []string{mldsaAlg},
		RevocationEndpoint:                                     fmt.Sprintf("%s/token/revoke", issuer),
		RevocationEndpointAuthMethodsSupported:                 []string{oidc.AuthMethodPrivateKeyJWT, oidc.AuthMethodClientAttestationJWT, oidc.AuthMethodSPIFFEJWT, oidc.AuthMethodSPIFFEWIT, oidc.AuthMethodSPIFFEX509, oidc.AuthMethodTLSClientAuth},
		RevocationEndpointAuthSigningAlgValuesSupported:        []string{mldsaAlg},
		DeviceAuthorizationEndpoint:                            fmt.Sprintf("%s/device/authorize", issuer),
		DpopSigningAlgValuesSupported:                          []string{mldsaAlg},
		AuthorizationResponseIssParameterSupported:             true,
		AuthorizationSigningAlgValuesSupported:                 []string{mldsaAlg},
		PushedAuthorizationRequestEndpoint:                     fmt.Sprintf("%s/par", issuer),
		PushedAuthorizationRequestEndpointAuthMethodsSupported: []string{oidc.AuthMethodPrivateKeyJWT, oidc.AuthMethodClientAttestationJWT, oidc.AuthMethodSPIFFEJWT, oidc.AuthMethodSPIFFEWIT, oidc.AuthMethodSPIFFEX509, oidc.AuthMethodTLSClientAuth},
		// RFC 8705 section 3: access and refresh tokens issued over mutual
		// TLS are bound to the client certificate (x5t#S256 confirmation).
		TlsClientCertificateBoundAccessTokens:  true,
		RequestParameterSupported:              true,
		ClientIdMetadataDocumentSupported:      true,
		RequestObjectSigningAlgValuesSupported: []string{mldsaAlg},
		AuthorizationDetailsTypesSupported:     []string{authDetailsType},
		// draft-ietf-oauth-identity-assertion-authz-grant-04 section 7:
		// advertise the ID-JAG token type this server can issue via token
		// exchange, and the ID-JAG grant profile it can process as a
		// Resource Authorization Server.
		IdentityChainingRequestedTokenTypesSupported: []string{oidc.IDJAGTokenType},
		// OpenID CIBA Core 1.0 section 4: poll mode only (no OP->client
		// callback surface), signed authentication requests with
		// elliptic-curve algorithms.
		BackchannelAuthenticationEndpoint:                         fmt.Sprintf("%s/bc-authorize", issuer),
		BackchannelTokenDeliveryModesSupported:                    []string{"poll"},
		BackchannelAuthenticationRequestSigningAlgValuesSupported: []string{"ES256", mldsaAlg},
		AuthorizationGrantProfilesSupported:                       []string{oidc.IDJAGGrantProfile},
		// draft-ietf-oauth-attestation-based-client-auth-11 section 8:
		// the attestation server signs ML-DSA-65 and the example client's
		// PoP is ML-DSA-65 — advertise exactly that.
		ClientAttestationSigningAlgValuesSupported:    []string{mldsaAlg},
		ClientAttestationPopSigningAlgValuesSupported: []string{mldsaAlg},
	}

	return md
}

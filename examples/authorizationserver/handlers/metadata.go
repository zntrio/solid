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

package handlers

import (
	"fmt"
	"net/http"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/token"
)

// Metadata handle OIDC Discovery HTTP requests.
func Metadata(issuer string, signer token.Serializer) http.Handler {
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
		TokenEndpointAuthSigningAlgValuesSupported:             []string{"ML-DSA-65"},
		CodeChallengeMethodsSupported:                          []string{"S256"},
		IntrospectionEndpoint:                                  fmt.Sprintf("%s/token/introspect", issuer),
		IntrospectionEndpointAuthMethodsSupported:              []string{oidc.AuthMethodPrivateKeyJWT, oidc.AuthMethodClientAttestationJWT, oidc.AuthMethodSPIFFEJWT, oidc.AuthMethodSPIFFEWIT, oidc.AuthMethodSPIFFEX509, oidc.AuthMethodTLSClientAuth},
		IntrospectionEndpointAuthSigningAlgValuesSupported:     []string{"ML-DSA-65"},
		RevocationEndpoint:                                     fmt.Sprintf("%s/token/revoke", issuer),
		RevocationEndpointAuthMethodsSupported:                 []string{oidc.AuthMethodPrivateKeyJWT, oidc.AuthMethodClientAttestationJWT, oidc.AuthMethodSPIFFEJWT, oidc.AuthMethodSPIFFEWIT, oidc.AuthMethodSPIFFEX509, oidc.AuthMethodTLSClientAuth},
		RevocationEndpointAuthSigningAlgValuesSupported:        []string{"ML-DSA-65"},
		DeviceAuthorizationEndpoint:                            fmt.Sprintf("%s/device/authorize", issuer),
		DpopSigningAlgValuesSupported:                          []string{"ML-DSA-65"},
		AuthorizationResponseIssParameterSupported:             true,
		AuthorizationSigningAlgValuesSupported:                 []string{"ML-DSA-65"},
		PushedAuthorizationRequestEndpoint:                     fmt.Sprintf("%s/par", issuer),
		PushedAuthorizationRequestEndpointAuthMethodsSupported: []string{oidc.AuthMethodPrivateKeyJWT, oidc.AuthMethodClientAttestationJWT, oidc.AuthMethodSPIFFEJWT, oidc.AuthMethodSPIFFEWIT, oidc.AuthMethodSPIFFEX509, oidc.AuthMethodTLSClientAuth},
		// RFC 8705 section 3: access and refresh tokens issued over mutual
		// TLS are bound to the client certificate (x5t#S256 confirmation).
		TlsClientCertificateBoundAccessTokens:  true,
		RequestParameterSupported:              true,
		ClientIdMetadataDocumentSupported:      true,
		RequestObjectSigningAlgValuesSupported: []string{"ML-DSA-65"},
		AuthorizationDetailsTypesSupported:     []string{"payment_initiation"},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean signed metadata
		md.SignedMetadata = ""

		// Create signed metadata
		signedMeta, err := signer.Serialize(r.Context(), md)
		if err != nil {
			http.Error(w, "unable to sign metadata", http.StatusInternalServerError)
			return
		}

		// Assign signed metadata
		md.SignedMetadata = signedMeta

		// Return JSON
		respond.WithJSON(w, http.StatusOK, md)
	})
}

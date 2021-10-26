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

	discoveryv1 "zntr.io/solid/api/gen/go/oidc/discovery/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/server/authorizationserver"
)

// Metadata handle OIDC Discovery HTTP requests.
func Metadata(as authorizationserver.AuthorizationServer, signer token.Signer) http.Handler {
	// Get issuer
	issuer := as.Issuer().String()

	// Prepare metadata
	md := &discoveryv1.ServerMetadata{
		Issuer:  issuer,
		JwksUri: fmt.Sprintf("%s/.well-known/jwks.json", issuer),
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
			oidc.GrantTypeJWTBearer,
			oidc.GrantTypeSAML2Bearer,
		},
		TokenEndpoint: fmt.Sprintf("%s/token", issuer),
		TokenEndpointAuthMethodsSupported: []string{
			oidc.AuthMethodPrivateKeyJWT,
		},
		TokenEndpointAuthSigningAlgValuesSupported:             []string{"ES384"},
		CodeChallengeMethodsSupported:                          []string{"S256"},
		IntrospectionEndpoint:                                  fmt.Sprintf("%s/token/introspect", issuer),
		IntrospectionEndpointAuthMethodsSupported:              []string{oidc.AuthMethodPrivateKeyJWT},
		IntrospectionEndpointAuthSigningAlgValuesSupported:     []string{"ES384"},
		RevocationEndpoint:                                     fmt.Sprintf("%s/token/revoke", issuer),
		RevocationEndpointAuthMethodsSupported:                 []string{oidc.AuthMethodPrivateKeyJWT},
		RevocationEndpointAuthSigningAlgValuesSupported:        []string{"ES384"},
		DeviceAuthorizationEndpoint:                            fmt.Sprintf("%s/device_authorization", issuer),
		DpopSigningAlgValuesSupported:                          []string{"ES256"},
		AuthorizationResponseIssParameterSupported:             true,
		AuthorizationSigningAlgValuesSupported:                 []string{"ES256", "ES384"},
		PushedAuthorizationRequestEndpoint:                     fmt.Sprintf("%s/par", issuer),
		PushedAuthorizationRequestEndpointAuthMethodsSupported: []string{oidc.AuthMethodPrivateKeyJWT},
		RequestParameterSupported:                              true,
		RequestObjectSigningAlgValuesSupported:                 []string{"ES384"},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean signed metadata
		md.SignedMetadata = ""

		// Create signed metadata
		signedMeta, err := signer.Sign(r.Context(), md)
		if err != nil {
			http.Error(w, "unable to sign metadata", http.StatusInternalServerError)
			return
		}

		// Assign signed metadata
		md.SignedMetadata = signedMeta

		// Return JSON
		withJSON(w, r, http.StatusOK, md)
	})
}

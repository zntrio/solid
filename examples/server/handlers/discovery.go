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

	discoveryv1 "go.zenithar.org/solid/api/gen/go/oidc/discovery/v1"
	"go.zenithar.org/solid/api/oidc"
)

// Metadata handle OIDC Discovery HTTP requests.
func Metadata(issuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		withJSON(w, r, http.StatusOK, &discoveryv1.ServerMetadata{
			Issuer:                             issuer,
			AuthorizationEndpoint:              fmt.Sprintf("%s/authorize", issuer),
			ResponseTypesSupported:             []string{"code"},
			GrantTypesSupported:                []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeAuthorizationCode},
			TokenEndpoint:                      fmt.Sprintf("%s/token", issuer),
			TokenEndpointAuthMethodsSupported:  []string{"private_key_jwt"},
			CodeChallengeMethodsSupported:      []string{"S256"},
			PushedAuthorizationRequestEndpoint: fmt.Sprintf("%s/par", issuer),
			PushedAuthorizationRequestEndpointAuthMethodsSupported: []string{"private_key_jwt"},
			IntrospectionEndpoint:                     fmt.Sprintf("%s/token/introspect", issuer),
			IntrospectionEndpointAuthMethodsSupported: []string{"private_key_jwt"},
			RevocationEndpoint:                        fmt.Sprintf("%s/token/revoke", issuer),
			RevocationEndpointAuthMethodsSupported:    []string{"private_key_jwt"},
		})
	})
}

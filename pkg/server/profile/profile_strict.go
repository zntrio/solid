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

package profile

import "zntr.io/solid/api/oidc"

var (
	strictProfile = &defaultServerProfile{
		clientProfiles: map[string]Client{
			// Server side web application
			oidc.ApplicationTypeServerSideWeb: &defaultClientProfile{
				grantTypesSupported: []string{
					oidc.GrantTypeAuthorizationCode,
				},
				responseTypesSupported: []string{
					oidc.ResponseTypeCode,
				},
				tokenEndpointAuthMethodsSupported: []string{
					oidc.AuthMethodPrivateKeyJWT,
				},
			},
			// Client side web application
			// Explicitly ignored (not supported in this profile)
			//
			// Desktop or mobile application
			oidc.ApplicationTypeNative: &defaultClientProfile{
				grantTypesSupported: []string{
					oidc.GrantTypeAuthorizationCode,
					oidc.GrantTypeRefreshToken,
				},
				responseTypesSupported: []string{
					oidc.ResponseTypeCode,
				},
				tokenEndpointAuthMethodsSupported: []string{
					oidc.AuthMethodPrivateKeyJWT,
				},
			},
			// Constrained device without browser (TV, Box, Game console, IoT, Car, etc.)
			oidc.ApplicationTypeDevice: &defaultClientProfile{
				grantTypesSupported: []string{
					oidc.GrantTypeDeviceCode,
					oidc.GrantTypeRefreshToken,
				},
				responseTypesSupported: []string{
					oidc.ResponseTypeCode,
				},
				tokenEndpointAuthMethodsSupported: []string{
					oidc.AuthMethodPrivateKeyJWT,
				},
			},
			// Service account
			oidc.ApplicationTypeService: &defaultClientProfile{
				grantTypesSupported: []string{
					oidc.GrantTypeClientCredentials,
				},
				responseTypesSupported: []string{
					oidc.ResponseTypeToken,
				},
				tokenEndpointAuthMethodsSupported: []string{
					oidc.AuthMethodPrivateKeyJWT,
				},
			},
		},
	}
)

// Strict returns a strict server profile.
func Strict() Server {
	return strictProfile
}

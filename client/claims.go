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

package client

import (
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/jwk"
)

// Token contains the token endpoint response fields used by this client.
// It replaces golang.org/x/oauth2.Token, which drags a dependency used only
// for this struct definition.
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty"`
	// Disclosures of a selectively disclosable access token
	// (draft-forten-oauth-sd-jwt-access-token-00 section 4).
	Disclosures []string `json:"disclosures,omitempty"`
}

// -----------------------------------------------------------------------------

type jsonJWKSResponse struct {
	jwk.Set `json:",inline"`
	Expires uint64 `json:"exp"`
}

type jsonTokenIntrospectionResponse struct {
	Active bool `json:"active"`
}

// jsonIntrospectionActor is the RFC 8693 section 4.4 nested act member of
// an introspection response: the acting party subject with its prior
// delegation chain.
type jsonIntrospectionActor struct {
	Sub string                  `json:"sub"`
	Act *jsonIntrospectionActor `json:"act,omitempty"`
}

// introspectionMetadata decodes the RFC 7662 section 2.2 member names of
// an introspection response into the token metadata fields (the wire
// names "sub"/"aud" differ from the proto field names). The optional
// members use pointer-to-pointer fields so decoding writes through to
// the target proto optional fields.
type introspectionMetadata struct {
	Subject              *string                         `json:"sub"`
	Audience             *string                         `json:"aud"`
	ClientId             *string                         `json:"client_id"`
	Scope                *string                         `json:"scope"`
	ExpiresAt            *uint64                         `json:"exp"`
	IssuedAt             *uint64                         `json:"iat"`
	NotBefore            *uint64                         `json:"nbf"`
	Acr                  **string                        `json:"acr"`
	AuthTime             **uint64                        `json:"auth_time"`
	AuthorizationDetails *[]*tokenv1.AuthorizationDetail `json:"authorization_details"`
}

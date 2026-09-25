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
}

// -----------------------------------------------------------------------------

type jsonJWKSResponse struct {
	jwk.Set `json:",inline"`
	Expires uint64 `json:"exp"`
}

type jsonTokenIntrospectionResponse struct {
	Active bool `json:"active"`
}

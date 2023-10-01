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
	"gopkg.in/square/go-jose.v2"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// RequestURIResponse contains all request_uri creation related information.
type RequestURIResponse struct {
	Issuer       string `json:"iss"`
	RequestURI   string `json:"request_uri"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// -----------------------------------------------------------------------------

type privateJWTClaims struct {
	JTI      string `json:"jti"`
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Expires  uint64 `json:"exp"`
	IssuedAt uint64 `json:"iat"`
	ACR      string `json:"acr"`
	AuthTime uint64 `json:"auth_time"`
}

type jsonError struct {
	ErrorCode        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type jsonRequestURIResponse struct {
	Error *jsonError `json:"inline"`

	RequestURI string `json:"request_uri"`
}

type jsonJWKSResponse struct {
	*jose.JSONWebKeySet `json:",inline"`
	Expires             uint64 `json:"exp"`
}

type jsonTokenIntrospectionResponse struct {
	*tokenv1.TokenMeta `json:",inline"`
	Active             bool                       `json:"active"`
	Confirmation       *tokenv1.TokenConfirmation `json:"cnf,omitempty"`
}

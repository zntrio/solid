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
	"encoding/json"
	"fmt"
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/storage"

	"github.com/square/go-jose/v3"
)

// PrivateKeyJWT authentication method.
func PrivateKeyJWT(clients storage.ClientReader) AuthenticationProcessor {
	return &privateKeyJWTAuthentication{
		clients: clients,
	}
}

type privateJWTClaims struct {
	JTI      string `json:"jti"`
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Expires  uint64 `json:"exp"`
	IssuedAt uint64 `json:"iat"`
}

type privateKeyJWTAuthentication struct {
	clients storage.ClientReader
}

//nolint:funlen,gocyclo // to refactor
func (p *privateKeyJWTAuthentication) Authenticate(ctx context.Context, req *corev1.ClientAuthenticationRequest) (*corev1.ClientAuthenticationResponse, error) {
	res := &corev1.ClientAuthenticationResponse{}

	// Validate request
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Validate required fields for this authentication method
	if req.ClientAssertionType == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must be defined")
	}
	if req.ClientAssertionType.Value != oidc.AssertionTypeJWTBearer {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must equals '%s'", oidc.AssertionTypeJWTBearer)
	}
	if req.ClientAssertion == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must be defined")
	}
	if req.ClientAssertion.Value == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must not be empty")
	}

	// Decode assertion without validation first
	rawAssertion, err := jose.ParseSigned(req.ClientAssertion.Value)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("assertion is syntaxically invalid: %w", err)
	}

	// Retrieve payload claims
	var claims privateJWTClaims
	if errDecode := json.Unmarshal(rawAssertion.UnsafePayloadWithoutVerification(), &claims); errDecode != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode payload claims: %w", errDecode)
	}

	// Validate claims
	if claims.Issuer == "" || claims.Subject == "" || claims.Audience == "" || claims.JTI == "" || claims.Expires == 0 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss, sub, aud, jti, exp are mandatory and not empty")
	}
	if claims.Issuer != claims.Subject {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss and sub must be identic")
	}
	if claims.Expires < uint64(time.Now().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("expired token")
	}

	// Check client in storage
	client, err := p.clients.Get(ctx, claims.Issuer)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("error during client retrieval: %w", err)
		}
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client not found")
	}

	// Retrieve JWK associated to the client
	if len(client.Jwks) == 0 {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client jwks is nil")
	}

	// Parse JWKS
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(client.Jwks, &jwks); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client jwks is invalid: %w", err)
	}

	// Try to validate assertion with one of keys
	if err := jwk.ValidateSignature(&jwks, rawAssertion); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client assertion is invalid: %w", err)
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}

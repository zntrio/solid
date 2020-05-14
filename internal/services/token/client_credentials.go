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

package token

import (
	"context"
	"fmt"
	"time"

	"github.com/dchest/uniuri"
	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/types"
)

func (s *service) clientCredentials(ctx context.Context, client *corev1.Client, req *corev1.TokenRequest) (*corev1.TokenResponse, error) {
	res := &corev1.TokenResponse{}
	grant := req.GetClientCredentials()

	// Check parameters
	if client == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to process with nil request")
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeClientCredentials) {
		res.Error = rfcerrors.UnsupportedGrantType("")
		return res, fmt.Errorf("client doesn't support 'client_credentials' as grant type")
	}

	// Create access token spec
	now := timeFunc()
	at := &corev1.Token{
		TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   uniuri.NewLen(jtiLength),
		Metadata: &corev1.TokenMeta{
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),
			ExpiresAt: uint64(now.Add(1 * time.Hour).Unix()),
			Scope:     grant.Scope,
			Audience:  grant.Audience,
		},
		Status: corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	var err error
	// Generate an access token
	at.Value, err = s.accessTokenGenerator.Generate(ctx, at.TokenId, at.Metadata)
	if err != nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to generate an accessToken: %w", err)
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, at); err != nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to register access token spec in token storage: %w", err)
	}

	// Assign response
	res.AccessToken = at

	// No error
	return res, nil
}

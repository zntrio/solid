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
	"net/url"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

//nolint:funlen,gocyclo // to refactor
func (s *service) refreshToken(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetRefreshToken()

	// Check parameters
	if client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil request")
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Check issuer syntax
	if req.Issuer == "" {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("issuer must not be blank")
	}

	_, err := url.ParseRequestURI(req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("issuer must be a valid url: %w", err)
	}

	if grant.RefreshToken == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("refresh_token must not be empty")
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeRefreshToken) {
		res.Error = rfcerrors.UnsupportedGrantType().Build()
		return res, fmt.Errorf("client doesn't support 'refresh_token' as grant type")
	}

	// Check given token
	rt, err := s.tokens.GetByValue(ctx, req.Issuer, grant.RefreshToken)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("unable to retrieve token '%s' from storage: %w", grant.RefreshToken, err)
	}

	// Check token
	if rt.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("refresh_token in not active")
	}
	if rt.TokenType != tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("refresh_token must not be empty")
	}
	if rt.Metadata == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("token doesn't have metadata")
	}

	// If expired
	if rt.Metadata.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("refresh_token is expired")
	}

	// Check client / refresh_token match
	if rt.Metadata.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("only requestor client must use the refresh_token")
	}

	// Generate access token
	at, err := s.generateAccessToken(ctx, client, rt.Metadata, rt.Confirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// If AT expiration is greater than RT expiration
	if at.Metadata.ExpiresAt > rt.Metadata.ExpiresAt {
		// Generate new refresh token
		newRt, err := s.generateRefreshToken(ctx, client, rt.Metadata, at.Confirmation)
		if err != nil {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to generate refresh token: %w", err)
		}

		// Revoke old refresh token
		if err := s.tokens.Revoke(ctx, req.Issuer, rt.TokenId); err != nil {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to revoke old refresh token '%s': %w", rt.Value, err)
		}

		// Assign new refresh token
		res.RefreshToken = newRt
	}

	// Assign access token
	res.AccessToken = at

	// No error
	return res, nil
}

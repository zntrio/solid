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
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/dchest/uniuri"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/sdk/types"
	"zntr.io/solid/pkg/server/storage"
)

//nolint:funlen,gocyclo // to refactor
func (s *service) tokenExchange(ctx context.Context, client *corev1.Client, req *corev1.TokenRequest) (*corev1.TokenResponse, error) {
	res := &corev1.TokenResponse{}

	// Check parameters
	if client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil request")
	}

	grant := req.GetTokenExchange()
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

	// Check subject token
	if grant.SubjectTokenType == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("subject_token_type must not be empty")
	}

	if grant.SubjectToken == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("subject_token must not be empty")
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeTokenExchange) {
		res.Error = rfcerrors.UnsupportedGrantType().Build()
		return res, fmt.Errorf("client doesn't support '%s' as grant type", oidc.GrantTypeTokenExchange)
	}

	// Dispatch according to subject_token_type.
	switch grant.SubjectTokenType {
	case oidc.TokenExchangeAccessTokenType:
		err = s.tokenExchangeAccessToken(ctx, client, req, res)
	default:
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("this subject_token_type is invalid or not supported")
	}

	if err != nil {
		return res, fmt.Errorf("unable to process token exchange: %w", err)
	}

	// No error
	return res, nil
}

func (s *service) tokenExchangeAccessToken(ctx context.Context, client *corev1.Client, req *corev1.TokenRequest, res *corev1.TokenResponse) error {
	// Check parameters
	if res == nil {
		return fmt.Errorf("unable to process with nil result")
	}
	if client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to process with nil request")
	}
	grant := req.GetTokenExchange()
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to process with nil grant")
	}

	// Check given token
	st, err := s.tokens.GetByValue(ctx, grant.SubjectToken)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return fmt.Errorf("unable to retrieve token '%s' from storage: %w", grant.SubjectToken, err)
	}

	// Check token
	if st.Status != corev1.TokenStatus_TOKEN_STATUS_ACTIVE {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token in not active")
	}
	if st.TokenType != corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token must not be empty")
	}
	if st.Metadata == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("token doesn't have metadata")
	}

	// If expired
	if st.Metadata.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token is expired")
	}

	// Prepare token metadata
	scope := st.Metadata.Scope
	if req.Scope != nil {
		scope = *req.Scope
	}

	// Create access token spec
	now := timeFunc()
	at := &corev1.Token{
		TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   uniuri.NewLen(jtiLength),
		Metadata: &corev1.TokenMeta{
			Issuer:    st.Metadata.Issuer,
			Subject:   st.Metadata.Subject,
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),
			ExpiresAt: uint64(now.Add(1 * time.Minute).Unix()),
			Scope:     scope,
		},
		Confirmation: st.Confirmation,
		Status:       corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// Add optional meta
	if req.Audience != nil {
		aud, err := s.resources.GetByURI(ctx, *req.Audience)
		if err != nil && errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("unable to validate audience: %w", err)
		}
		if errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.InvalidTarget().Build()
			return fmt.Errorf("audience '%s' not found", *req.Audience)
		}

		// Assign urn
		at.Metadata.Audience = aud.Urn
	}

	// Generate an access token
	at.Value, err = s.accessTokenGen.Generate(ctx, at)
	if err != nil {
		return fmt.Errorf("unable to generate an accessToken: %w", err)
	}

	// Check generator value
	if at.Value == "" {
		return fmt.Errorf("accessTokenGenerator generated an empty value")
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, at); err != nil {
		return fmt.Errorf("unable to register access token spec in token storage: %w", err)
	}

	// Assign access token
	res.Issuer = st.Metadata.Issuer
	res.AccessToken = at
	res.IssuedTokenType = types.StringRef(oidc.TokenExchangeAccessTokenType)

	// Assign scope if different
	if st.Metadata.Scope != scope {
		res.Scope = types.StringRef(scope)
	}

	// No error
	return nil
}

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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	random "zntr.io/solid/sdk/random"
)

const (
	// jtiLength of 16 base62 characters carries ~95 bits of entropy
	// (RFC 9700 section 4.12.2 recommends at least 64 bits of entropy for
	// token identifiers).
	jtiLength = 16
)

var timeFunc = time.Now

// newGrantID mints a unique identifier for an authorization grant family.
func newGrantID() string {
	return random.String(16)
}

// containsString reports whether list contains the value.
func containsString(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func (s *service) generateAccessToken(ctx context.Context, client *clientv1.Client, meta *tokenv1.TokenMeta, cnf *tokenv1.TokenConfirmation) (*tokenv1.Token, error) {
	var err error

	// Create access token spec
	now := timeFunc()
	at := &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   random.String(jtiLength),
		Metadata: &tokenv1.TokenMeta{
			Issuer:    meta.Issuer,
			Subject:   meta.Subject,
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),                    //nolint:gosec // unix time is non-negative
			NotBefore: uint64(now.Unix() + 1),                //nolint:gosec // unix time is non-negative
			ExpiresAt: uint64(now.Add(1 * time.Hour).Unix()), //nolint:gosec // unix time is non-negative
			Scope:     meta.Scope,
			Audience:  meta.Audience,
			GrantId:   meta.GrantId,
			// RFC 9396 section 9: the granted authorization details ride
			// the token metadata into access-token claims and
			// introspection responses.
			AuthorizationDetails: meta.AuthorizationDetails,
		},
		Confirmation: cnf,
		Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// Generate an access token
	at.Value, err = s.accessTokenGen.Generate(ctx, at)
	if err != nil {
		return nil, fmt.Errorf("unable to generate an accessToken: %w", err)
	}

	// Check generator value
	if at.Value == "" {
		return nil, fmt.Errorf("accessTokenGenerator generated an empty value")
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, meta.Issuer, at); err != nil {
		return nil, fmt.Errorf("unable to register access token spec in token storage: %w", err)
	}

	// No error
	return at, nil
}

func (s *service) generateRefreshToken(ctx context.Context, client *clientv1.Client, meta *tokenv1.TokenMeta, cnf *tokenv1.TokenConfirmation) (*tokenv1.Token, error) {
	var err error

	// Create access token spec
	now := timeFunc()
	at := &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
		TokenId:   random.String(jtiLength),
		Metadata: &tokenv1.TokenMeta{
			Issuer:    meta.Issuer,
			Subject:   meta.Subject,
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),                  //nolint:gosec // unix time is non-negative
			NotBefore: uint64(now.Unix() + 1),              //nolint:gosec // unix time is non-negative
			ExpiresAt: uint64(now.AddDate(0, 0, 7).Unix()), //nolint:gosec // unix time is non-negative
			Scope:     meta.Scope,
			Audience:  meta.Audience,
			GrantId:   meta.GrantId,
			// RFC 9396 section 9: authorization details survive refresh
			// token rotation so narrowed families stay narrowed.
			AuthorizationDetails: meta.AuthorizationDetails,
		},
		Confirmation: cnf,
		Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// Generate an access token
	at.Value, err = s.refreshTokenGen.Generate(ctx, at)
	if err != nil {
		return nil, fmt.Errorf("unable to generate an refresh token: %w", err)
	}

	// Check generator value
	if at.Value == "" {
		return nil, fmt.Errorf("refreshTokenGenerator generated an empty value")
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, meta.Issuer, at); err != nil {
		return nil, fmt.Errorf("unable to register refresh token spec in token storage: %w", err)
	}

	// No error
	return at, nil
}

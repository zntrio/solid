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
	"strings"
	"time"

	"github.com/dchest/uniuri"
	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

const (
	jtiLength = 8
)

var (
	timeFunc         = time.Now
	tokenTypeStrings = strings.Split("invalid|unknown|access_token|refesh_token|id_token", "|")
)

func (s *service) generateAccessToken(ctx context.Context, client *corev1.Client, meta *corev1.TokenMeta) (*corev1.Token, error) {
	var err error

	// Create access token spec
	now := timeFunc()
	at := &corev1.Token{
		TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   uniuri.NewLen(jtiLength),
		Metadata: &corev1.TokenMeta{
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),
			ExpiresAt: uint64(now.Add(1 * time.Hour).Unix()),
			Scope:     meta.Scope,
			Audience:  meta.Audience,
		},
		Status: corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// Generate an access token
	at.Value, err = s.tokenGen.Generate(ctx, at.TokenId, at.Metadata)
	if err != nil {
		return nil, fmt.Errorf("unable to generate an accessToken: %w", err)
	}

	// Check generator value
	if at.Value == "" {
		return nil, fmt.Errorf("accessTokenGenerator generated an empty value")
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, at); err != nil {
		return nil, fmt.Errorf("unable to register access token spec in token storage: %w", err)
	}

	// No error
	return at, nil
}

func (s *service) generateRefreshToken(ctx context.Context, client *corev1.Client, meta *corev1.TokenMeta) (*corev1.Token, error) {
	var err error

	// Create access token spec
	now := timeFunc()
	at := &corev1.Token{
		TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
		TokenId:   uniuri.NewLen(jtiLength),
		Metadata: &corev1.TokenMeta{
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),
			ExpiresAt: uint64(now.AddDate(0, 0, 7).Unix()),
			Scope:     meta.Scope,
			Audience:  meta.Audience,
		},
		Status: corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// Generate an access token
	at.Value, err = s.tokenGen.Generate(ctx, at.TokenId, at.Metadata)
	if err != nil {
		return nil, fmt.Errorf("unable to generate an refresh token: %w", err)
	}

	// Check generator value
	if at.Value == "" {
		return nil, fmt.Errorf("accessTokenGenerator generated an empty value")
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, at); err != nil {
		return nil, fmt.Errorf("unable to register refresh token spec in token storage: %w", err)
	}

	// No error
	return at, nil
}

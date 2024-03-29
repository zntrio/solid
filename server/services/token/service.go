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

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

type service struct {
	accessTokenGen            token.Generator
	refreshTokenGen           token.Generator
	clients                   storage.ClientReader
	authorizationRequests     storage.AuthorizationRequestReader
	authorizationCodeSessions storage.AuthorizationCodeSession
	deviceCodeSessions        storage.DeviceCodeSession
	tokens                    storage.Token
	resources                 storage.ResourceReader
}

// New build and returns an authorization service implementation.
func New(accessTokenGen token.Generator, refreshTokenGen token.Generator, clients storage.ClientReader, authorizationRequests storage.AuthorizationRequestReader, authorizationCodeSessions storage.AuthorizationCodeSession, deviceCodeSessions storage.DeviceCodeSession, tokens storage.Token, resources storage.ResourceReader) services.Token {
	return &service{
		accessTokenGen:            accessTokenGen,
		refreshTokenGen:           refreshTokenGen,
		clients:                   clients,
		authorizationRequests:     authorizationRequests,
		authorizationCodeSessions: authorizationCodeSessions,
		deviceCodeSessions:        deviceCodeSessions,
		tokens:                    tokens,
		resources:                 resources,
	}
}

// ----------------------------------------------------------------------------

func (s *service) Token(ctx context.Context, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}

	// Validate request
	if err := validateRequest(ctx, req); err != nil {
		res.Error = err
		return res, fmt.Errorf("unable to validate token request")
	}

	// Retrieve client information
	client, err := s.clients.Get(ctx, req.Client.ClientId)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidClient().Build()
		}
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Dispatch request according to grant_type
	switch req.GrantType {
	case oidc.GrantTypeClientCredentials:
		res, err = s.clientCredentials(ctx, client, req)
	case oidc.GrantTypeAuthorizationCode:
		res, err = s.authorizationCode(ctx, client, req)
	case oidc.GrantTypeDeviceCode:
		res, err = s.deviceCode(ctx, client, req)
	case oidc.GrantTypeRefreshToken:
		res, err = s.refreshToken(ctx, client, req)
	case oidc.GrantTypeTokenExchange:
		res, err = s.tokenExchange(ctx, client, req)
	default:
		// Validated by the front validator but added for defensive principle.
		res.Error = rfcerrors.InvalidGrant().Build()
		err = fmt.Errorf("invalid grant_type in request '%s'", req.GrantType)
	}

	// No error
	return res, err
}

// -----------------------------------------------------------------------------

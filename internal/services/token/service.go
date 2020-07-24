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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/internal/services"
	"zntr.io/solid/pkg/sdk/generator"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/storage"
)

type service struct {
	tokenGen                  generator.Token
	idGen                     generator.Identity
	clients                   storage.ClientReader
	authorizationRequests     storage.AuthorizationRequestReader
	authorizationCodeSessions storage.AuthorizationCodeSession
	deviceCodeSessions        storage.DeviceCodeSession
	tokens                    storage.Token
}

// New build and returns an authorization service implementation.
func New(tokenGen generator.Token, idGen generator.Identity, clients storage.ClientReader, authorizationRequests storage.AuthorizationRequestReader, authorizationCodeSessions storage.AuthorizationCodeSession, deviceCodeSessions storage.DeviceCodeSession, tokens storage.Token) services.Token {
	return &service{
		tokenGen:                  tokenGen,
		idGen:                     idGen,
		clients:                   clients,
		authorizationRequests:     authorizationRequests,
		authorizationCodeSessions: authorizationCodeSessions,
		deviceCodeSessions:        deviceCodeSessions,
		tokens:                    tokens,
	}
}

// ----------------------------------------------------------------------------

func (s *service) Token(ctx context.Context, req *corev1.TokenRequest) (*corev1.TokenResponse, error) {
	res := &corev1.TokenResponse{}

	// Validate request
	if err := validateRequest(ctx, req); err != nil {
		res.Error = err
		return res, fmt.Errorf("unable to validate token request")
	}

	// Retrieve client information
	client, err := s.clients.Get(ctx, req.Client.ClientId)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError("")
		} else {
			res.Error = rfcerrors.InvalidClient("")
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
	default:
		// Validated by the front validator but added for defensive principle.
		res.Error = rfcerrors.InvalidGrant("")
		err = fmt.Errorf("invalid grant_type in request '%s'", req.GrantType)
	}

	// No error
	return res, err
}

// -----------------------------------------------------------------------------

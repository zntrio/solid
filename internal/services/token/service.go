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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/token"
)

type service struct {
	accessTokenGenerator  token.AccessTokenGenerator
	idTokenGenerator      token.IDTokenGenerator
	clients               storage.ClientReader
	authorizationRequests storage.AuthorizationRequestReader
}

const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeClientCredentials = "client_credentials"
	grantTypeDeviceCode        = "device_code"
	grantTypeRefreshToken      = "refresh_token"
)

// New build and returns an authorization service implementation.
func New(accessTokenGenerator token.AccessTokenGenerator, idTokenGenerator token.IDTokenGenerator, clients storage.ClientReader, authorizationRequests storage.AuthorizationRequestReader) services.Token {
	return &service{
		accessTokenGenerator:  accessTokenGenerator,
		idTokenGenerator:      idTokenGenerator,
		clients:               clients,
		authorizationRequests: authorizationRequests,
	}
}

// ----------------------------------------------------------------------------

func (s *service) Token(ctx context.Context, req *corev1.TokenRequest) (*corev1.TokenResponse, error) {
	res := &corev1.TokenResponse{}

	// Validate request
	if err := ValidateRequest(ctx, req); err != nil {
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
	case grantTypeClientCredentials:
		res, err = s.clientCredentials(ctx, client, req)
	case grantTypeAuthorizationCode:
		res, err = s.authorizationCode(ctx, client, req)
	case grantTypeDeviceCode:
		res, err = s.deviceCode(ctx, client, req)
	case grantTypeRefreshToken:
		res, err = s.refreshToken(ctx, client, req)
	}

	// No error
	return res, err
}

// -----------------------------------------------------------------------------

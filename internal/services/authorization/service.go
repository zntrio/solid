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

package authorization

import (
	"context"
	"fmt"
	"strings"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/authorization"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/types"
)

type service struct {
	codeGenerator         authorization.CodeGenerator
	clients               storage.ClientReader
	authorizationRequests storage.AuthorizationRequest
}

// New build and returns an authorization service implementation.
func New(codeGenerator authorization.CodeGenerator, clients storage.ClientReader, authorizationRequests storage.AuthorizationRequest) services.Authorization {
	return &service{
		codeGenerator:         codeGenerator,
		clients:               clients,
		authorizationRequests: authorizationRequests,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *corev1.AuthorizationRequest) (*corev1.AuthorizationResponse, error) {
	res := &corev1.AuthorizationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check request reference usage
	if req.RequestUri != nil {
		// Check if request uri exists in storage
		ar, err := s.authorizationRequests.GetByRequestURI(ctx, req.RequestUri.Value)
		if err != nil {
			if err != storage.ErrNotFound {
				res.Error = rfcerrors.ServerError("")
			} else {
				res.Error = rfcerrors.InvalidRequest("")
			}
			return res, fmt.Errorf("unable to retrieve request by uri: %w", err)
		}

		// Burn after read
		if err := s.authorizationRequests.Delete(ctx, req.RequestUri.Value); err != nil {
			if err != storage.ErrNotFound {
				res.Error = rfcerrors.ServerError("")
			} else {
				res.Error = rfcerrors.InvalidRequest("")
			}
			return res, fmt.Errorf("unable to retrieve request by uri: %w", err)
		}

		// Override request
		req = ar
	}

	// Delegate to real authorize process
	_, res, err := s.authorize(ctx, false, req)
	return res, err
}

func (s *service) Register(ctx context.Context, req *corev1.RegistrationRequest) (*corev1.RegistrationResponse, error) {
	res := &corev1.RegistrationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to process nil request")
	}

	// Delegate to real authorize process
	requestURI, authRes, err := s.authorize(ctx, true, req.Request)
	if err != nil {
		res.Error = authRes.Error
		return res, err
	}

	// Assemble result
	res.ExpiresIn = 90
	res.RequestUri = requestURI

	// No error
	return res, nil
}

// -----------------------------------------------------------------------------

func (s *service) authorize(ctx context.Context, par bool, req *corev1.AuthorizationRequest) (string, *corev1.AuthorizationResponse, error) {
	res := &corev1.AuthorizationResponse{}

	// Validate request
	var err error
	if res.Error, err = validateAuthorization(ctx, req); err != nil {
		return "", res, fmt.Errorf("unable to validate authorization request: %w", err)
	}

	// Check client ID
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError(req.State)
		} else {
			res.Error = rfcerrors.InvalidRequest(req.State)
		}
		return "", res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeAuthorizationCode) {
		res.Error = rfcerrors.UnsupportedGrantType(req.State)
		return "", res, fmt.Errorf("client doesn't support 'authorization_code' as grant type")
	}

	// Validate client response_type
	if !types.StringArray(client.ResponseTypes).Contains(req.ResponseType) {
		res.Error = rfcerrors.InvalidRequest(req.State)
		return "", res, fmt.Errorf("client doesn't support `%s` as response type", req.ResponseType)
	}

	// Validate client response_types
	if !types.StringArray(client.RedirectUris).Contains(req.RedirectUri) {
		res.Error = rfcerrors.InvalidRequest(req.State)
		return "", res, fmt.Errorf("client doesn't support `%s` as redirect_uri type", req.RedirectUri)
	}

	// Generate authorization code
	var code string
	// Skip code generation in registration mode
	if !par {
		if code, err = s.codeGenerator.Generate(ctx); err != nil {
			res.Error = rfcerrors.ServerError(req.State)
			return "", res, fmt.Errorf("unable to generate authorization code: %w", err)
		}
	}

	// Check scopes
	scopes := types.StringArray(strings.Fields(req.Scope))

	// If has openid scopes
	if scopes.Contains(oidc.ScopeOpenID) {
		// OIDC Tokens required

		// https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
		if scopes.Contains(oidc.ScopeOfflineAccess) {
			// Check if prompt is given
			if req.Prompt == nil {
				scopes.Remove(oidc.ScopeOfflineAccess)
			} else if req.Prompt.Value != "consent" {
				// Prompt value must contain `consent` for offline_access request
				scopes.Remove(oidc.ScopeOfflineAccess)
			}
		}

		// Reassign cleaned scopes
		req.Scope = strings.Join(scopes, " ")
	}

	// Store authorization request
	requestURI, err := s.authorizationRequests.Register(ctx, req)
	if err != nil {
		res.Error = rfcerrors.ServerError(req.State)
		return "", res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Skip assignation is registration mode
	if !par {
		// Assign code to response
		res.Code = code

		// Assign state to response
		res.State = req.State
	}

	// No error
	return requestURI, res, nil
}

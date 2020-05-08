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
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/authorization"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/types"
)

type service struct {
	codeGenerator         authorization.CodeGenerator
	clients               storage.ClientReader
	authorizationRequests storage.AuthorizationRequestWriter
}

// New build and returns an authorization service implementation.
func New(codeGenerator authorization.CodeGenerator, clients storage.ClientReader, authorizationRequests storage.AuthorizationRequestWriter) services.Authorization {
	return &service{
		codeGenerator:         codeGenerator,
		clients:               clients,
		authorizationRequests: authorizationRequests,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *corev1.AuthorizationRequest) (*corev1.AuthorizationResponse, error) {
	res := &corev1.AuthorizationResponse{}

	// Validate request
	if err := ValidateAuthorization(ctx, req); err != nil {
		res.Error = err
		return res, fmt.Errorf("unable to validate authorization request")
	}

	// Check client ID
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError(req.State)
		} else {
			res.Error = rfcerrors.InvalidRequest(req.State)
		}
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains("authorization_code") {
		res.Error = rfcerrors.UnsupportedGrantType(req.State)
		return res, fmt.Errorf("client doesn't support 'authorization_code' as grant type")
	}

	// Validate client response_type
	if !types.StringArray(client.ResponseTypes).Contains(req.ResponseType) {
		res.Error = rfcerrors.InvalidRequest(req.State)
		return res, fmt.Errorf("client doesn't support `%s` as response type", req.ResponseType)
	}

	// Validate client response_types
	if !types.StringArray(client.RedirectUris).Contains(req.RedirectUri) {
		res.Error = rfcerrors.InvalidRequest(req.State)
		return res, fmt.Errorf("client doesn't support `%s` as redirect_uri type", req.RedirectUri)
	}

	// Generate authorization code
	var code string
	if code, err = s.codeGenerator.Generate(ctx); err != nil {
		res.Error = rfcerrors.ServerError(req.State)
		return res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Check scopes
	scopes := types.StringArray(strings.Fields(req.Scope))

	// If has openid scopes
	if scopes.Contains("openid") {
		// OIDC Tokens required

		// https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
		if scopes.Contains("offline_access") {
			// Check if prompt is given
			if req.Prompt == nil {
				scopes.Remove("offline_access")
			} else if req.Prompt.Value != "consent" {
				// Prompt value must contain `consent` for offline_access request
				scopes.Remove("offline_access")
			}
		}

		// Reassign cleaned scopes
		req.Scope = strings.Join(scopes, " ")
	}

	// Store authorization request
	requestURI, err := s.authorizationRequests.Register(ctx, req)
	if err != nil {
		res.Error = rfcerrors.ServerError(req.State)
		return res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Assign code to response
	res.Code = code

	// Assign state to response
	res.State = req.State

	// Assign request_uri to the response
	res.RequestUri = requestURI

	// No error
	return res, nil
}

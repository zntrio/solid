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
	"regexp"
	"strings"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/types"
)

var requestURIMatcher = regexp.MustCompile(`urn\:solid\:[A-Za-z0-9]{32}`)

const (
	desiredMinStateValueLength         = 32
	desiredMinNonceValueLength         = 8
	desiredMinCodeChallengeValueLength = 43
	desiredMaxCodeChallengeValueLength = 128
)

type service struct {
	clients               storage.ClientReader
	authorizationRequests storage.AuthorizationRequest
	sessions              storage.SessionWriter
}

// New build and returns an authorization service implementation.
func New(clients storage.ClientReader, authorizationRequests storage.AuthorizationRequest, sessions storage.SessionWriter) services.Authorization {
	return &service{
		clients:               clients,
		authorizationRequests: authorizationRequests,
		sessions:              sessions,
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
		// Check request_uri syntax
		if !requestURIMatcher.MatchString(req.RequestUri.Value) {
			res.Error = rfcerrors.InvalidRequest("")
			return res, fmt.Errorf("request_uri is syntaxically invalid '%s'", req.RequestUri.Value)
		}

		// Check if request uri exists in storage
		ar, err := s.authorizationRequests.Get(ctx, req.RequestUri.Value)
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
	publicErr, err := s.validate(ctx, req)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	// Create an authorization session
	code, err := s.sessions.Register(ctx, &corev1.Session{
		Subject: "",
		Request: req,
	})
	if err != nil {
		res.Error = rfcerrors.ServerError(req.State)
		return res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Assign code to response
	res.Code = code

	// Assign state to response
	res.State = req.State

	return res, err
}

func (s *service) Register(ctx context.Context, req *corev1.RegistrationRequest) (*corev1.RegistrationResponse, error) {
	res := &corev1.RegistrationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check client authentication context
	if req.Client == nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("client must not be nil")
	}

	// Check client_id
	if req.Client.ClientId == "" {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("client_id must not be empty")
	}

	// Check client existence
	client, err := s.clients.Get(ctx, req.Client.ClientId)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Validate authorization request
	publicErr, err := s.validate(ctx, req.Request)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	// Check registration / client association
	if req.Request.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to register request for another client")
	}

	// Register the authorization request
	requestURI, err := s.authorizationRequests.Register(ctx, req.Request)
	if err != nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to register authorization request: %w", err)
	}

	// Assemble result
	res.ExpiresIn = 90
	res.RequestUri = requestURI

	// No error
	return res, nil
}

// -----------------------------------------------------------------------------

func (s *service) validate(ctx context.Context, req *corev1.AuthorizationRequest) (*corev1.Error, error) {
	// Check req nullity
	if req == nil {
		return rfcerrors.InvalidRequest(""), fmt.Errorf("unable to process nil request")
	}

	// Validate request attributes
	if req.State == "" {
		return rfcerrors.InvalidRequest("<missing>"), fmt.Errorf("state, scope, response_type, client_id, redirect_uri, code_challenge, code_challenge_method parameters are mandatory")
	}
	if len(req.State) < desiredMinStateValueLength {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("state too short")
	}

	if req.Scope == "" || req.ResponseType == "" || req.ClientId == "" || req.RedirectUri == "" || req.CodeChallenge == "" || req.CodeChallengeMethod == "" || req.Nonce == "" {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("state, nonce, scope, response_type, client_id, redirect_uri, code_challenge, code_challenge_method parameters are mandatory")
	}

	if len(req.Nonce) < desiredMinNonceValueLength {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("nonce too short")
	}

	if req.CodeChallengeMethod != oidc.CodeChallengeMethodSha256 {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("invalid or unsupported code_challenge_method '%s'", req.CodeChallengeMethod)
	}

	if len(req.CodeChallenge) != desiredMinCodeChallengeValueLength {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("code_challenge too short")
	}

	// Check client ID
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		if err != storage.ErrNotFound {
			return rfcerrors.ServerError(req.State), fmt.Errorf("unable to retrieve client details: %w", err)
		}

		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeAuthorizationCode) {
		return rfcerrors.UnsupportedGrantType(req.State), fmt.Errorf("client doesn't support 'authorization_code' as grant type")
	}

	// Validate client response_type
	if !types.StringArray(client.ResponseTypes).Contains(req.ResponseType) {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("client doesn't support `%s` as response type", req.ResponseType)
	}

	// Validate client response_types
	if !types.StringArray(client.RedirectUris).Contains(req.RedirectUri) {
		return rfcerrors.InvalidRequest(req.State), fmt.Errorf("client doesn't support `%s` as redirect_uri type", req.RedirectUri)
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

	// No error
	return nil, nil
}

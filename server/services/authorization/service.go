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
	"net/url"
	"strings"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

const (
	desiredMinNonceValueLength         = 8
	desiredMinStateValueLength         = 32
	desiredMinCodeChallengeValueLength = 43
)

type service struct {
	clients                   storage.ClientReader
	authorizationRequests     storage.AuthorizationRequest
	authorizationCodeSessions storage.AuthorizationCodeSessionWriter
	codeGenerator             generator.AuthorizationCode
	requestURIGenerator       generator.RequestURI
}

// New build and returns an authorization service implementation.
func New(clients storage.ClientReader, authorizationRequests storage.AuthorizationRequest, authorizationCodeSessions storage.AuthorizationCodeSessionWriter, codeGenerator generator.AuthorizationCode, requestURIGenerator generator.RequestURI) services.Authorization {
	return &service{
		clients:                   clients,
		authorizationRequests:     authorizationRequests,
		authorizationCodeSessions: authorizationCodeSessions,
		codeGenerator:             codeGenerator,
		requestURIGenerator:       requestURIGenerator,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *flowv1.AuthorizeRequest) (*flowv1.AuthorizeResponse, error) {
	res := &flowv1.AuthorizeResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check authoriaztion request
	if req.Request == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil authorization request")
	}

	// Check issuer
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process empty issuer")
	}

	// Check subject
	if req.Subject == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process empty subject")
	}

	// Check request reference usage
	if req.Request.RequestUri != nil {
		// Check request_uri syntax
		if err := s.requestURIGenerator.Validate(ctx, req.Issuer, *req.Request.RequestUri); err != nil {
			res.Error = rfcerrors.InvalidRequest().Build()
			return res, fmt.Errorf("request_uri is syntaxically invalid '%s'", *req.Request.RequestUri)
		}

		// Check if request uri exists in storage
		ar, err := s.authorizationRequests.Get(ctx, req.Issuer, *req.Request.RequestUri)
		if err != nil {
			if err != storage.ErrNotFound {
				res.Error = rfcerrors.ServerError().Build()
			} else {
				res.Error = rfcerrors.InvalidRequest().Build()
			}
			return res, fmt.Errorf("unable to retrieve request by uri: %w", err)
		}

		// Burn after read
		if err := s.authorizationRequests.Delete(ctx, req.Issuer, *req.Request.RequestUri); err != nil {
			if err != storage.ErrNotFound {
				res.Error = rfcerrors.ServerError().Build()
			} else {
				res.Error = rfcerrors.InvalidRequest().Build()
			}
			return res, fmt.Errorf("unable to retrieve request by uri: %w", err)
		}

		// Override request
		req.Request = ar
	}

	// Delegate to real authorize process
	publicErr, err := s.validate(ctx, req.Request)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	// Create an authorization code
	code, err := s.codeGenerator.Generate(ctx, req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().State(req.Request.State).Build()
		return res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Create an authorization session
	expiresIn, err := s.authorizationCodeSessions.Register(ctx, req.Issuer, code, &sessionv1.AuthorizationCodeSession{
		Issuer:  req.Issuer,
		Subject: req.Subject,
		Request: req.Request,
	})
	if err != nil {
		res.Error = rfcerrors.ServerError().State(req.Request.State).Build()
		return res, fmt.Errorf("unable to register authorization session: %w", err)
	}

	// Assign code to response
	res.Code = code
	// Assign state to response
	res.State = req.Request.State
	// Assign redirectUri to response
	res.RedirectUri = req.Request.RedirectUri
	// Assign client
	res.ClientId = req.Request.ClientId
	// Assign expiration
	res.ExpiresIn = expiresIn
	// Assign issuer
	res.Issuer = req.Issuer

	return res, err
}

func (s *service) Register(ctx context.Context, req *flowv1.RegistrationRequest) (*flowv1.RegistrationResponse, error) {
	res := &flowv1.RegistrationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check issuer
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process empty issuer")
	}

	// Check client authentication context
	if req.Client == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client must not be nil")
	}

	// Check authorization request is nill
	if req.Request == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("authorization request must not be nil")
	}

	// Check nested request
	if req.Request.RequestUri != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to register nested request")
	}

	// Validate authorization request
	publicErr, err := s.validate(ctx, req.Request)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	// Check registration / client association
	if req.Request.ClientId != req.Client.ClientId {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to register request for another client")
	}

	// Generate request uri
	requestURI, err := s.requestURIGenerator.Generate(ctx, req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate request uri: %w", err)
	}

	// Register the authorization request
	expiresIn, err := s.authorizationRequests.Register(ctx, req.Issuer, requestURI, req.Request)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to register authorization request: %w", err)
	}

	// Assemble result
	res.ExpiresIn = expiresIn
	res.RequestUri = requestURI
	res.Issuer = req.Issuer

	// No error
	return res, nil
}

// -----------------------------------------------------------------------------

//nolint:gocyclo,gocognit // to refactor
func (s *service) validate(ctx context.Context, req *flowv1.AuthorizationRequest) (*corev1.Error, error) {
	// Check req nullity
	if req == nil {
		return rfcerrors.InvalidRequest().Build(), fmt.Errorf("unable to process nil request")
	}

	// Validate request attributes
	if req.State == "" {
		return rfcerrors.InvalidRequest().Build(), fmt.Errorf("state, scope, response_type, client_id, redirect_uri, code_challenge, code_challenge_method parameters are mandatory")
	}
	if len(req.State) < desiredMinStateValueLength {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("state too short")
	}

	if req.Scope == "" || req.ResponseType == "" || req.ClientId == "" || req.RedirectUri == "" || req.CodeChallenge == "" || req.CodeChallengeMethod == "" || req.Audience == "" || req.Nonce == "" {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("audience, state, scope, response_type, client_id, redirect_uri, code_challenge, code_challenge_method, nonce parameters are mandatory")
	}

	if len(req.Nonce) < desiredMinNonceValueLength {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("nonce too short")
	}

	if req.CodeChallengeMethod != oidc.CodeChallengeMethodSha256 {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("invalid or unsupported code_challenge_method '%s'", req.CodeChallengeMethod)
	}

	if len(req.CodeChallenge) != desiredMinCodeChallengeValueLength {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("code_challenge too short")
	}

	// Prepare redirection uri
	_, err := url.ParseRequestURI(req.RedirectUri)
	if err != nil {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("redirect_uri has an invalid syntax: %w", err)
	}

	// Validate response mode if specified.
	switch req.ResponseType {
	case oidc.ResponseTypeCode:
	case oidc.ResponseTypeToken:
	default:
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("unsupported response_type")
	}

	// Validate response mode if specified.
	if req.ResponseMode != nil {
		// Validate response mode
		switch *req.ResponseMode {
		case oidc.ResponseModeQuery, oidc.ResponseModeFragment, oidc.ResponseModeFormPost:
		case oidc.ResponseModeJWT, oidc.ResponseModeFormPOSTJWT, oidc.ResponseModeQueryJWT, oidc.ResponseModeFragmentJWT:
		default:
			return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("unsupported response_mode")
		}

		// 	Expand alias according to response type.
		if *req.ResponseMode == oidc.ResponseModeJWT {
			switch req.ResponseType {
			case oidc.ResponseTypeCode:
				req.ResponseMode = types.StringRef(oidc.ResponseModeQueryJWT)
			case oidc.ResponseTypeToken:
				req.ResponseMode = types.StringRef(oidc.ResponseModeFragmentJWT)
			}
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
			} else if *req.Prompt != oidc.PromptConsent {
				// Prompt value must contain `consent` for offline_access request
				scopes.Remove(oidc.ScopeOfflineAccess)
			}
		}

		// Reassign cleaned scopes
		req.Scope = strings.Join(scopes, " ")
	}

	// No error
	return s.validateClientCapabilities(ctx, req)
}

func (s *service) validateClientCapabilities(ctx context.Context, req *flowv1.AuthorizationRequest) (*corev1.Error, error) {
	// Check client ID
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		if err != storage.ErrNotFound {
			return rfcerrors.ServerError().State(req.State).Build(), fmt.Errorf("unable to retrieve client details: %w", err)
		}

		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeAuthorizationCode) {
		return rfcerrors.UnsupportedGrantType().State(req.State).Build(), fmt.Errorf("client doesn't support 'authorization_code' as grant type")
	}

	// Validate client response_type
	if !types.StringArray(client.ResponseTypes).Contains(req.ResponseType) {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("client doesn't support `%s` as response type", req.ResponseType)
	}

	// Validate client response_types
	if !types.StringArray(client.RedirectUris).Contains(req.RedirectUri) {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("client doesn't support `%s` as redirect_uri type", req.RedirectUri)
	}

	// Validate client response_modes
	if req.ResponseMode != nil {
		if !types.StringArray(client.ResponseModes).Contains(*req.ResponseMode) {
			return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("client doesn't support `%s` as response_mode", *req.ResponseMode)
		}
	}

	// No error
	return nil, nil
}

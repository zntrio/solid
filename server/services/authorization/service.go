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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	random "zntr.io/solid/sdk/random"
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
	authzDetailsValidator     authzdetails.Validator
}

// isUnreservedChar reports whether the rune belongs to the unreserved set
// defined by RFC 3986 section 2.3: ALPHA / DIGIT / "-" / "." / "_" / "~".
// RFC 7636 section 4.1 restricts code challenges to this set.
func isUnreservedChar(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-' || r == '.' || r == '_' || r == '~':
		return true
	default:
		return false
	}
}

// New build and returns an authorization service implementation.
func New(clients storage.ClientReader, authorizationRequests storage.AuthorizationRequest, authorizationCodeSessions storage.AuthorizationCodeSessionWriter, codeGenerator generator.AuthorizationCode, requestURIGenerator generator.RequestURI, authzDetailsValidator authzdetails.Validator) services.Authorization {
	return &service{
		clients:                   clients,
		authorizationRequests:     authorizationRequests,
		authorizationCodeSessions: authorizationCodeSessions,
		codeGenerator:             codeGenerator,
		requestURIGenerator:       requestURIGenerator,
		authzDetailsValidator:     authzDetailsValidator,
	}
}

// -----------------------------------------------------------------------------

//nolint:gocyclo,funlen // linear RFC 6749-ordered validation chain; each guard is a protocol requirement
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

	// RFC 9207 section 2: the authorization response — success or error —
	// carries the AS issuer identifier so clients can detect mix-up attacks
	// (also listed by draft-ietf-oauth-security-topics-update-03 section
	// 2.2.2 as the approved countermeasure); set it before any failure path.
	res.Issuer = req.Issuer

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

		// Atomically consume the pushed request: burn-after-read without
		// a Get/Delete interleaving window (RFC 9126 section 2.2
		// single-use request_uri). A concurrent second authorize on the
		// same request_uri gets storage.ErrNotFound.
		ar, err := s.authorizationRequests.DeleteAndGet(ctx, req.Issuer, *req.Request.RequestUri)
		if err != nil {
			if !errors.Is(err, storage.ErrNotFound) {
				res.Error = rfcerrors.ServerError().Build()
			} else {
				res.Error = rfcerrors.InvalidRequest().Build()
			}
			return res, fmt.Errorf("unable to retrieve request by uri: %w", err)
		}

		// RFC 9126 section 2.2: the pushed request is bound to the client
		// that registered it; a different client presenting the same
		// request_uri is rejected (prevents request object injection).
		if req.Client == nil || ar.ClientId != req.Client.ClientId {
			res.Error = rfcerrors.InvalidRequest().State(ar.State).Build()
			return res, fmt.Errorf("request_uri was not issued to the requesting client")
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

	// The authenticated front-channel client must match the client_id of
	// the (possibly referenced) authorization request: a request object or
	// pushed request bound to another client must not be consumable under
	// different credentials (RFC 9101 section 5 client_id / iss binding).
	if req.Client != nil && req.Request.ClientId != req.Client.ClientId {
		res.Error = rfcerrors.InvalidRequest().State(req.Request.State).Build()
		return res, fmt.Errorf("client_id mismatch between client and request object")
	}
	// Create an authorization code
	code, err := s.codeGenerator.Generate(ctx, req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().State(req.Request.State).Build()
		return res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Create an authorization session; the lifecycle status starts at ACTIVE
	// and only the sdk/session state machine may advance it.
	//
	// RFC 9449 section 10: when the authorization request carries a DPoP
	// key binding (dpop_jkt — from the signed request object or inherited
	// from the pushed request), persist it with the code session so
	// redemption can enforce key continuity.
	session := &sessionv1.AuthorizationCodeSession{
		Issuer:  req.Issuer,
		Subject: req.Subject,
		Request: req.Request,
		// Grant family identifier, minted at code issuance and inherited by
		// every token minted from this grant (RFC 9700 section 4.14.2).
		GrantId: random.String(16),
		Status:  sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_ACTIVE,
	}
	if req.Request.DpopJkt != nil && *req.Request.DpopJkt != "" {
		session.Confirmation = &tokenv1.TokenConfirmation{Jkt: *req.Request.DpopJkt}
	}
	expiresIn, err := s.authorizationCodeSessions.Register(ctx, req.Issuer, code, session)
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

	// RFC 9449 section 5: bind the DPoP key confirmed at the PAR endpoint
	// to the stored authorization request, so that the request_uri consumes
	// into an authorization code bound to that key (RFC 9449 section 10
	// code binding). The stored dpop_jkt is the single carrier: it flows
	// through Authorize into the code session and is enforced at
	// redemption.
	if req.Confirmation != nil && req.Confirmation.Jkt != "" {
		req.Request.DpopJkt = types.StringRef(req.Confirmation.Jkt)
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

	if utf8.RuneCountInString(req.CodeChallenge) != desiredMinCodeChallengeValueLength {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("code_challenge length must be exactly %d characters", desiredMinCodeChallengeValueLength)
	}
	if strings.IndexFunc(req.CodeChallenge, func(r rune) bool { return !isUnreservedChar(r) }) >= 0 {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("code_challenge contains characters outside the unreserved set")
	}

	// Prepare redirection uri
	_, err := url.ParseRequestURI(req.RedirectUri)
	if err != nil {
		return rfcerrors.InvalidRequest().State(req.State).Build(), fmt.Errorf("redirect_uri has an invalid syntax: %w", err)
	}

	// Validate response type: this authorization server profile only supports
	// the authorization code flow; the implicit flow (response_type=token) is
	// deliberately not offered.
	switch req.ResponseType {
	case oidc.ResponseTypeCode:
	default:
		return rfcerrors.UnsupportedResponseType().State(req.State).Build(), fmt.Errorf("unsupported response_type '%s'", req.ResponseType)
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
		if *req.ResponseMode == oidc.ResponseModeJWT && req.ResponseType == oidc.ResponseTypeCode {
			req.ResponseMode = new(oidc.ResponseModeQueryJWT)
		}
	}

	// Validate authorization details when the request carries them
	// (RFC 9396 section 5): a nil validator fails closed — any non-empty
	// authorization_details set is rejected.
	if len(req.AuthorizationDetails) > 0 {
		if err := s.authzDetailsValidator.Validate(ctx, req.AuthorizationDetails); err != nil {
			return rfcerrors.InvalidAuthorizationDetails().State(req.State).Build(), fmt.Errorf("invalid authorization_details: %w", err)
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
		if !errors.Is(err, storage.ErrNotFound) {
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

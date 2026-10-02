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

package backchannel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/encoding/protojson"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	sessionstate "zntr.io/solid/sdk/session"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

type service struct {
	clients               storage.ClientReader
	sessions              storage.BackchannelAuthenticationSession
	authReqIDs            generator.AuthReqID
	hints                 HintResolver
	authzDetailsValidator authzdetails.Validator
	requestSigningAlgs    []string
}

const (
	// defaultSessionTTL bounds the backchannel authentication session
	// lifetime (CIBA section 7.1: the default expiry is between 300
	// and 3600 seconds).
	defaultSessionTTL = 300 * time.Second
	// defaultPollInterval is the required polling interval advertised
	// at backchannel authentication time (CIBA section 7.3).
	defaultPollInterval uint64 = 5
	// maxRequestedExpiry caps a requested auth_req_id lifetime
	// (CIBA section 7.1: the requested_expiry value must not exceed
	// 3600 seconds).
	maxRequestedExpiry uint64 = 3600
)

// bindingMessagePattern constrains the binding_message: the CD/AD
// anti-phishing interlock, promoted to REQUIRED by solid (4-64 chars,
// charset [A-Za-z0-9._-], CIBA section 7.1).
var bindingMessagePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{4,64}$`)

// New builds and returns a backchannel authentication service
// implementation (OpenID CIBA Core 1.0).
func New(clients storage.ClientReader, sessions storage.BackchannelAuthenticationSession, authReqIDs generator.AuthReqID, hints HintResolver, authzDetailsValidator authzdetails.Validator, requestSigningAlgorithms []string) services.BackchannelAuthentication {
	return &service{
		clients:               clients,
		sessions:              sessions,
		authReqIDs:            authReqIDs,
		hints:                 hints,
		authzDetailsValidator: authzDetailsValidator,
		requestSigningAlgs:    requestSigningAlgorithms,
	}
}

var timeFunc = time.Now

// -----------------------------------------------------------------------------

//nolint:funlen,gocyclo,govet // linear CIBA-section-ordered validation chain; each guard is a protocol requirement
func (s *service) Authorize(ctx context.Context, req *flowv1.BackchannelAuthenticationRequest) (*flowv1.BackchannelAuthenticationResponse, error) {
	res := &flowv1.BackchannelAuthenticationResponse{}

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

	// Check client_id
	if req.ClientId == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_id must not be empty")
	}

	// Check client existence
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to retrieve client details: %w", err)
		}
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client not found")
	}
	if client == nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to process with nil client")
	}

	// Validate client capabilities (CIBA section 13: unauthorized_client
	// when the client is not authorized to use this authentication flow).
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeCIBA) {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return res, fmt.Errorf("client doesn't support '%s' as grant type", oidc.GrantTypeCIBA)
	}

	// Defense-in-depth (CIBA section 7.1.1): when a signed request is
	// used, no authentication request parameter may appear outside it.
	if req.Request != nil && hasParameterOutsideRequestObject(req) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("authentication request parameters must not appear outside the request object")
	}

	// Signed authentication request (CIBA section 7.1.1): verify, then map
	// the JWT claims onto the request fields.
	if req.Request != nil {
		if err := s.applySignedRequest(ctx, client, req); err != nil {
			res.Error = rfcerrors.InvalidRequest().Build()
			return res, fmt.Errorf("signed authentication request is invalid: %w", err)
		}
	}

	// Hint cardinality (CIBA section 7.2 step 3): exactly one of
	// login_hint, login_hint_token, id_token_hint.
	if hintCount(req) != 1 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("exactly one of login_hint, login_hint_token, id_token_hint must be provided")
	}

	// binding_message (solid promotion): REQUIRED, the CD/AD anti-phishing
	// interlock (CIBA section 7.1).
	if req.BindingMessage == nil || !bindingMessagePattern.MatchString(*req.BindingMessage) {
		res.Error = rfcerrors.InvalidBindingMessage().Build()
		return res, fmt.Errorf("binding_message must be 4-64 chars in [A-Za-z0-9._-]")
	}

	// Scope must contain openid (CIBA section 7.1).
	if req.Scope == nil || !types.StringArray(strings.Fields(*req.Scope)).Contains(oidc.ScopeOpenID) {
		res.Error = rfcerrors.InvalidScope().Build()
		return res, fmt.Errorf("scope must contain 'openid'")
	}

	// RFC 9396 section 5: validate requested authorization details against
	// the deployment registry; a nil validator rejects any non-empty set
	// (fail-closed).
	if len(req.AuthorizationDetails) > 0 {
		if err := s.authzDetailsValidator.Validate(ctx, req.AuthorizationDetails); err != nil {
			res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
			return res, fmt.Errorf("authorization_details are invalid: %w", err)
		}
	}

	// Resolve the end-user subject from the hint (CIBA section 7.2 step 4).
	subject, err := s.hints.Resolve(ctx, req)
	if err != nil || strings.TrimSpace(subject) == "" {
		res.Error = rfcerrors.UnknownUserID().Build()
		return res, fmt.Errorf("unable to resolve end-user: %w", err)
	}

	// Honor requested_expiry within (0, 3600]; default otherwise
	// (CIBA section 7.1).
	ttl := defaultSessionTTL
	if v := req.GetRequestedExpiry(); v > 0 && v <= maxRequestedExpiry {
		ttl = time.Duration(v) * time.Second
	}

	// Generate auth_req_id
	authReqID, err := s.authReqIDs.Generate(ctx, req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate auth_req_id: %w", err)
	}

	// Prepare session. The absolute expiry is stamped so that the token
	// grant can distinguish an expired session from a pending one
	// (CIBA section 11).
	session := &sessionv1.BackchannelAuthenticationSession{
		Issuer:    req.Issuer,
		Client:    client,
		Request:   req,
		Scope:     req.Scope,
		Audience:  req.Audience,
		AuthReqId: authReqID,
		Subject:   &subject,
		Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
		ExpiresAt: uint64(timeFunc().Add(ttl).Unix()), //nolint:gosec // unix time is non-negative
		// Advertised polling interval (CIBA section 7.3); the token grant
		// enforces it with slow_down (CIBA section 11).
		PollInterval: defaultPollInterval,
		// RFC 9396 section 3: authorization details requested at
		// backchannel authentication time are fixed on the session and
		// consented at approval time.
		AuthorizationDetails: req.AuthorizationDetails,
	}

	// RFC 9449 section 10 analog: when the request declares a DPoP key
	// (dpop_jkt, inside the signed request object), the session is bound
	// to it and the token request MUST prove possession of that same key.
	if jkt := req.GetDpopJkt(); jkt != "" {
		session.Confirmation = &tokenv1.TokenConfirmation{Jkt: jkt}
	}

	// RFC 9700 section 4.12.2: the cross-device channel is an
	// authentication-device-mediated flow, so the CIBA grant never grants
	// offline access — strip it from the session scope before storing.
	if req.Scope != nil {
		scopes := types.StringArray(strings.Fields(*req.Scope))
		scopes.Remove(oidc.ScopeOfflineAccess)
		filtered := strings.Join(scopes, " ")
		session.Scope = &filtered
	}

	// Store session
	expiresIn, err := s.sessions.Register(ctx, req.Issuer, authReqID, session)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to create backchannel authentication session: %w", err)
	}
	_ = expiresIn

	// Assign auth_req_id
	res.AuthReqId = authReqID
	// Set expiration from the honored TTL
	res.ExpiresIn = uint64(ttl.Seconds())
	// Polling interval
	res.Interval = defaultPollInterval
	// Assign issuer
	res.Issuer = req.Issuer

	// No error
	return res, nil
}

func (s *service) Validate(ctx context.Context, req *flowv1.BackchannelAuthenticationValidationRequest) (*flowv1.BackchannelAuthenticationValidationResponse, error) {
	res := &flowv1.BackchannelAuthenticationValidationResponse{}

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

	// Check auth_req_id
	if req.AuthReqId == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process blank auth_req_id")
	}

	// Check subject
	if req.Subject == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process blank subject")
	}

	// Resolve session
	session, err := s.sessions.GetByAuthReqID(ctx, req.Issuer, req.AuthReqId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}
	if session == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", req.AuthReqId)
	}
	if session.Request == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("session has nil request for '%s'", req.AuthReqId)
	}
	if session.Client == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("session has nil client for '%s'", req.AuthReqId)
	}

	// Check expiration
	if session.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.TokenExpired().Build()
		return res, fmt.Errorf("auth_req_id '%s' is expired", req.AuthReqId)
	}

	// Apply the session state machine: PENDING -> VALIDATED is the only
	// legal transition; anything else (double approval, replay) is
	// rejected by construction.
	if err := sessionstate.BackchannelAuthenticationTransition(session.Status, sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("auth_req_id '%s' cannot be validated: %w", req.AuthReqId, err)
	}

	// Update session
	session.Subject = new(req.Subject)
	session.Status = sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED

	// Update ephemeral storage
	if err := s.sessions.Validate(ctx, req.Issuer, req.AuthReqId, session); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("auth_req_id '%s' could not be validated: %w", req.AuthReqId, err)
	}

	// Delete request
	if err := s.sessions.Delete(ctx, req.Issuer, req.AuthReqId); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("auth_req_id '%s' could not be deleted: %w", req.AuthReqId, err)
	}

	// No error
	return res, nil
}

// Deny refuses a backchannel authentication request: the session moves to
// the terminal DENIED state and the token grant reports access_denied on
// the next poll (CIBA section 11).
func (s *service) Deny(ctx context.Context, req *flowv1.BackchannelAuthenticationValidationRequest) (*flowv1.BackchannelAuthenticationValidationResponse, error) {
	res := &flowv1.BackchannelAuthenticationValidationResponse{}

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

	// Check auth_req_id
	if req.AuthReqId == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process blank auth_req_id")
	}

	// Resolve session
	session, err := s.sessions.GetByAuthReqID(ctx, req.Issuer, req.AuthReqId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}

	// Check session
	if session == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", req.AuthReqId)
	}

	// Apply the session state machine: PENDING -> DENIED is the only legal
	// transition; anything else (double handling, replay) is rejected by
	// construction.
	if err := sessionstate.BackchannelAuthenticationTransition(session.Status, sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_DENIED); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("auth_req_id '%s' cannot be denied: %w", req.AuthReqId, err)
	}

	// Update session
	session.Status = sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_DENIED

	// Update ephemeral storage
	if err := s.sessions.Validate(ctx, req.Issuer, req.AuthReqId, session); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("auth_req_id '%s' could not be denied: %w", req.AuthReqId, err)
	}

	// No error
	return res, nil
}

// -----------------------------------------------------------------------------

// applySignedRequest verifies a signed authentication request (CIBA
// section 7.1.1) against the client's registered JWKS and maps its claims
// onto the request fields. The client is already authenticated at this
// endpoint: iss, aud, signature and time-window failures all map to
// invalid_request.
//
//nolint:funlen,gocyclo,govet // linear CIBA-section-7.1.1-ordered validation chain; each guard is a protocol requirement
func (s *service) applySignedRequest(ctx context.Context, client *clientv1.Client, req *flowv1.BackchannelAuthenticationRequest) error {
	// Decode without cryptographic verification first to enforce the
	// algorithm allowlist before processing claims.
	t, parts, err := gojwt.NewParser().ParseUnverified(*req.Request, gojwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("request object is syntactically invalid: %w", err)
	}
	if len(parts) != 3 {
		return fmt.Errorf("request object is not a JWS compact serialization")
	}

	// Enforce the algorithm allowlist (elliptic curves only, repo rule).
	if !types.StringArray(s.requestSigningAlgs).Contains(t.Method.Alg()) {
		return fmt.Errorf("request object algorithm %q is not supported", t.Method.Alg())
	}

	// Retrieve payload claims
	claims, ok := t.Claims.(gojwt.MapClaims)
	if !ok {
		return fmt.Errorf("unable to decode request object claims")
	}

	// iss MUST be the authenticated client (CIBA section 7.1.1).
	if iss, ok := claims["iss"].(string); !ok || iss != req.ClientId {
		return fmt.Errorf("request object 'iss' claim must equal the client_id")
	}

	// aud MUST contain the issuer (CIBA section 7.1.1); the JSON Web
	// Token profile permits the array form.
	if !audClaimContains(claims["aud"], req.Issuer) {
		return fmt.Errorf("request object 'aud' claim must contain '%s'", req.Issuer)
	}

	// Time window: exp REQUIRED and in the future; iat REQUIRED; nbf, when
	// present, not in the future (CIBA section 7.1.1).
	now := timeFunc().Unix()
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= float64(now) {
		return fmt.Errorf("request object 'exp' claim is mandatory and must be in the future")
	}
	if _, ok := claims["iat"].(float64); !ok {
		return fmt.Errorf("request object 'iat' claim is mandatory")
	}
	if nbf, ok := claims["nbf"].(float64); ok && nbf > float64(now) {
		return fmt.Errorf("request object 'nbf' claim must not be in the future")
	}

	// jti REQUIRED and non-empty (CIBA section 7.1.1).
	if jti, ok := claims["jti"].(string); !ok || jti == "" {
		return fmt.Errorf("request object 'jti' claim is mandatory")
	}

	// Verify the signature against the client's registered JWKS
	// (elliptic-curve algs only via the allowlist above).
	if len(client.Jwks) == 0 {
		return fmt.Errorf("client jwks is nil")
	}
	jwks, err := jwk.Parse(client.Jwks)
	if err != nil {
		return fmt.Errorf("client jwks is invalid: %w", err)
	}
	if err := jwk.ValidateSignature(jwks, *req.Request, s.requestSigningAlgs); err != nil {
		return fmt.Errorf("request object signature is invalid: %w", err)
	}

	// Map claims onto request fields (CIBA section 7.1.1: the request
	// object carries the authentication request parameters as claims).
	if v, ok := claims["scope"].(string); ok {
		req.Scope = new(v)
	}
	if v, ok := claims["audience"].(string); ok {
		req.Audience = new(v)
	}
	if v, ok := claims["acr_values"].(string); ok {
		req.AcrValues = new(v)
	}
	if v, ok := claims["login_hint"].(string); ok {
		req.LoginHint = new(v)
	}
	if v, ok := claims["login_hint_token"].(string); ok {
		req.LoginHintToken = new(v)
	}
	if v, ok := claims["id_token_hint"].(string); ok {
		req.IdTokenHint = new(v)
	}
	if v, ok := claims["binding_message"].(string); ok {
		req.BindingMessage = new(v)
	}

	// dpop_jkt claim (RFC 9449 section 10): DPoP key thumbprint the
	// token-endpoint polls MUST prove possession of.
	if v, ok := claims["dpop_jkt"].(string); ok {
		req.DpopJkt = new(v)
	}

	// requested_expiry: Number or NumericDate per section 7.1.1.
	switch v := claims["requested_expiry"].(type) {
	case float64:
		req.RequestedExpiry = new(uint64(v))
	case string:
		var parsed uint64
		if _, err := fmt.Sscanf(v, "%d", &parsed); err == nil {
			req.RequestedExpiry = new(parsed)
		}
	}

	// authorization_details claim (RFC 9396 with CIBA section 7.1): decode
	// each entry as a JSON object onto its proto representation.
	if raw, ok := claims["authorization_details"]; ok && raw != nil {
		entries, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("authorization_details claim must be an array")
		}
		details := make([]*tokenv1.AuthorizationDetail, 0, len(entries))
		for i, entry := range entries {
			buf, err := json.Marshal(entry)
			if err != nil {
				return fmt.Errorf("unable to decode authorization_details[%d] claim: %w", i, err)
			}
			detail := &tokenv1.AuthorizationDetail{}
			if err := protojson.Unmarshal(buf, detail); err != nil {
				return fmt.Errorf("unable to decode authorization_details[%d] claim: %w", i, err)
			}
			details = append(details, detail)
		}
		req.AuthorizationDetails = details
	}

	_ = ctx
	return nil
}

// hasParameterOutsideRequestObject reports whether any CIBA authentication
// request parameter is set on the message alongside the request object
// (CIBA section 7.1.1: parameters MUST NOT appear outside it).
func hasParameterOutsideRequestObject(req *flowv1.BackchannelAuthenticationRequest) bool {
	return req.Scope != nil ||
		req.Audience != nil ||
		req.AcrValues != nil ||
		req.LoginHint != nil ||
		req.LoginHintToken != nil ||
		req.IdTokenHint != nil ||
		req.BindingMessage != nil ||
		req.DpopJkt != nil ||
		req.RequestedExpiry != nil ||
		len(req.AuthorizationDetails) > 0
}

// hintCount counts the CIBA identification hints set on the request.
func hintCount(req *flowv1.BackchannelAuthenticationRequest) int {
	count := 0
	for _, hint := range []string{req.GetLoginHint(), req.GetLoginHintToken(), req.GetIdTokenHint()} {
		if hint != "" {
			count++
		}
	}
	return count
}

// audClaimContains reports whether the aud claim value — a string or, per
// the JSON Web Token profile, an array of strings — contains the expected
// issuer (CIBA section 7.1.1).
func audClaimContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

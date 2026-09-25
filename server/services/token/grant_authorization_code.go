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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

const (
	desiredAuthorizationCodeMaxValueLength = 1024
	desiredCodeVerifiedMinValueLength      = 43
	desiredCodeVerifiedMaxValueLength      = 128
)

//nolint:gocyclo,funlen // linear RFC-ordered validation chain; each guard is a protocol requirement
func (s *service) authorizationCode(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetAuthorizationCode()

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeAuthorizationCode)
	if err != nil {
		res.Error = publicErr
		return res, err
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Validate request
	if grant.Code == "" || grant.CodeVerifier == "" || grant.RedirectUri == "" {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code, code_verifier and redirect_uri are mandatory")
	}

	// Validate code length
	if utf8.RuneCountInString(grant.Code) > desiredAuthorizationCodeMaxValueLength {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code is too long")
	}

	// Validate code verifier: RFC 7636 section 4.1 bounds are expressed in
	// characters (runes), not bytes; and every character MUST come from the
	// unreserved set ALPHA / DIGIT / "-" / "." / "_" / "~".
	if utf8.RuneCountInString(grant.CodeVerifier) < desiredCodeVerifiedMinValueLength {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code_verifier is too short")
	}
	if utf8.RuneCountInString(grant.CodeVerifier) > desiredCodeVerifiedMaxValueLength {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code_verifier is too long")
	}
	if strings.IndexFunc(grant.CodeVerifier, func(r rune) bool { return !isUnreservedChar(r) }) >= 0 {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code_verifier contains characters outside the unreserved set")
	}

	// Retrieve authorization request from code
	// RFC 9700 section 4.5: single-use codes are enforced with an atomic
	// consume; a concurrent double redeem gets storage.ErrNotFound.
	ar, err := s.authorizationCodeSessions.DeleteAndGet(ctx, req.Issuer, grant.Code)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, fmt.Errorf("unable to retrieve authorization request from code '%s': %w", grant.Code, err)
	}
	// Check if not nil
	if ar.Request == nil {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("retrieve authorization request is invalid '%s'", grant.Code)
	}

	// Enforce the session state machine invariant: the atomic consume in
	// storage stamps the session CONSUMED; a session surfacing with any other
	// status (UNSPECIFIED, ACTIVE) indicates storage corruption or a
	// non-conforming implementation and is rejected by construction.
	if ar.Status != sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED {
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid authorization request: consumed session status is invalid '%s'", ar.Status)
	}

	// Ensure the authorization code was issued to the client that is redeeming
	// it, as required by RFC 6749 section 4.1.3.
	if ar.Request.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid authorization request: code was not issued to client '%s'", client.ClientId)
	}

	// RFC 9449 section 10: when the code session is bound to a DPoP key
	// (confirmation set at authorization time — from the signed request
	// object's dpop_jkt parameter or the PAR-endpoint proof), the token
	// request MUST prove possession of that same key. The grant's dpop_jkt
	// carries the thumbprint verified from the DPoP proof at the token
	// endpoint; anything else is a proof-key swap.
	if ar.Confirmation != nil && ar.Confirmation.Jkt != "" {
		if grant.DpopJkt == nil || *grant.DpopJkt == "" {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("authorization code is bound to a DPoP key but no proof confirmation was presented")
		}
		if !types.SecureCompareString(ar.Confirmation.Jkt, *grant.DpopJkt) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("DPoP key does not match the authorization code binding")
		}
	}

	// RFC 9449 section 10, token-endpoint binding: when the grant itself
	// carries a dpop_jkt (the proof thumbprint verified at the token
	// endpoint), a confirmation presented by the token request MUST match
	// that binding; a mismatch is a proof-key swap against the grant.
	if grant.DpopJkt != nil && *grant.DpopJkt != "" {
		presentedJkt := ""
		if req.TokenConfirmation != nil {
			presentedJkt = req.TokenConfirmation.Jkt
		}
		if presentedJkt == "" {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("authorization grant is bound to a DPoP key but no proof confirmation was presented")
		}
		if !types.SecureCompareString(presentedJkt, *grant.DpopJkt) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("DPoP key does not match the authorization grant binding")
		}
	}

	// RFC 9700 section 4.2.4: on double redemption the code session is already
	// burned (storage.ErrNotFound above); revocation of tokens minted from the
	// grant is enforced at refresh-token family level (grant_refresh_token.go),
	// where the replayed token carries its grant identifier.

	// Validate redirectUri
	if ar.Request.RedirectUri != grant.RedirectUri {
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid authorization request: request_uri from request '%s' and token '%s' must be identic", ar.Request.RedirectUri, grant.RedirectUri)
	}
	if !types.StringArray(client.RedirectUris).Contains(grant.RedirectUri) {
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid authorization request: request_uri from request '%s' and client '%s' must be validated", grant.RedirectUri, client.RedirectUris)
	}

	// Check PKCE verifier
	// https://www.rfc-editor.org/rfc/rfc7636.txt
	switch ar.Request.CodeChallengeMethod {
	case oidc.CodeChallengeMethodSha256:
		h := sha256.Sum256([]byte(grant.CodeVerifier))
		computedVerifier := base64.RawURLEncoding.EncodeToString(h[:])
		if !types.SecureCompareString(computedVerifier, ar.Request.CodeChallenge) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("unable to validate PKCE code_verifier and code_challenge for client '%s'", client.ClientId)
		}
	default:
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid code_challenge_method in request `%s`", ar.Request.CodeChallengeMethod)
	}

	// RFC 9396 section 6: when the token request carries
	// authorization_details, every requested entry MUST match (proto
	// equality) one entry consented at authorization time; the client may
	// only narrow the granted set. When the request omits them, the AS
	// grants the full consented set (section 7: the AS determines the
	// resulting authorization_details at its discretion).
	grantedDetails := req.AuthorizationDetails
	if len(grantedDetails) == 0 {
		grantedDetails = ar.Request.AuthorizationDetails
	} else if err := validateAuthorizationDetailsSubset(req.AuthorizationDetails, ar.Request.AuthorizationDetails); err != nil {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return res, fmt.Errorf("invalid authorization request: %w", err)
	}

	// RFC 8707 section 2: resource indicators requested at authorization
	// time are validated against the registered resource registry; an
	// unknown indicator is an invalid_target. The validated audience is
	// what gets minted into the token — never a verbatim copy of the
	// request parameter.
	for _, resourceURI := range ar.Request.Resource {
		if _, errRes := s.resources.GetByURI(ctx, resourceURI); errRes != nil {
			if errors.Is(errRes, storage.ErrNotFound) {
				res.Error = rfcerrors.InvalidTarget().State(ar.Request.State).Build()
				return res, fmt.Errorf("unknown resource indicator '%s'", resourceURI)
			}
			res.Error = rfcerrors.ServerError().State(ar.Request.State).Build()
			return res, fmt.Errorf("unable to validate resource indicator '%s': %w", resourceURI, errRes)
		}
	}

	// Validate scopes
	scopes := types.StringArray(strings.Fields(ar.Request.Scope))

	// Generate OpenID tokens (AT / RT / IDT)
	if !scopes.Contains(oidc.ScopeOpenID) {
		// No OpenID scope: no token to mint.
		return res, nil
	}

	// Mint the access token for the granted scopes.
	if err := s.mintAuthorizationCodeTokens(ctx, client, req, ar, scopes, grantedDetails, res); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, err
	}

	// No error
	return res, nil
}

// mintAuthorizationCodeTokens generates the access token — and, when the
// offline_access scope was granted with a consent prompt, the refresh
// token — for a redeemed authorization code session.
func (s *service) mintAuthorizationCodeTokens(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest, ar *sessionv1.AuthorizationCodeSession, scopes types.StringArray, grantedDetails []*tokenv1.AuthorizationDetail, res *flowv1.TokenResponse) error {
	// Generate access token
	at, err := s.generateAccessToken(ctx, client, &tokenv1.TokenMeta{
		Issuer:               req.Issuer,
		Subject:              ar.Subject,
		Audience:             ar.Request.Audience,
		Scope:                ar.Request.Scope,
		GrantId:              ar.GrantId,
		AuthorizationDetails: grantedDetails,
	}, req.TokenConfirmation)
	if err != nil {
		return fmt.Errorf("unable to generate access token: %w", err)
	}

	// Check if request has offline_access to generate refresh_token
	if scopes.Contains(oidc.ScopeOfflineAccess) {
		// Generate refresh token
		rt, err := s.generateRefreshToken(ctx, client, &tokenv1.TokenMeta{
			Issuer:               req.Issuer,
			Subject:              ar.Subject,
			Audience:             ar.Request.Audience,
			Scope:                ar.Request.Scope,
			GrantId:              ar.GrantId,
			AuthorizationDetails: grantedDetails,
		}, at.Confirmation)
		if err != nil {
			return fmt.Errorf("unable to generate refresh token: %w", err)
		}

		// Assign response
		res.RefreshToken = rt
	}

	res.AccessToken = at
	res.AuthorizationDetails = grantedDetails

	// No error
	return nil
}

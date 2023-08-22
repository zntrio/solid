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
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
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

//nolint:funlen,gocyclo,gocognit // to refactor
func (s *service) authorizationCode(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetAuthorizationCode()

	// Check parameters
	if client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil request")
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Check issuer syntax
	if req.Issuer == "" {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("issuer must not be blank")
	}

	_, err := url.ParseRequestURI(req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("issuer must be a valid url: %w", err)
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeAuthorizationCode) {
		res.Error = rfcerrors.UnsupportedGrantType().Build()
		return res, fmt.Errorf("client doesn't support 'authorization_code' as grant type")
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

	// Validate code verifier
	if len(grant.CodeVerifier) < desiredCodeVerifiedMinValueLength {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code_verifier is too short")
	}
	if len(grant.CodeVerifier) > desiredCodeVerifiedMaxValueLength {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code_verifier is too long")
	}

	// Retrieve authorization request from code
	ar, err := s.authorizationCodeSessions.Get(ctx, req.Issuer, grant.Code)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, fmt.Errorf("unable to retrieve authorization request from code '%s': %w", grant.Code, err)
	}

	// Check if not nil
	if ar.Request == nil {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("retrieve authorization request is invalid '%s': %w", grant.Code, err)
	}

	// Delete session
	err = s.authorizationCodeSessions.Delete(ctx, req.Issuer, grant.Code)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to remove authorization session from code '%s': %w", grant.Code, err)
	}

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
		if computedVerifier != ar.Request.CodeChallenge {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("unable to validate PKCE code_verifier `%s` and code_challenge `%s`", computedVerifier, ar.Request.CodeChallenge)
		}
	default:
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid code_challenge_method in request `%s`", ar.Request.CodeChallengeMethod)
	}

	// Validate scopes
	scopes := types.StringArray(strings.Fields(ar.Request.Scope))

	// Generate OpenID tokens (AT / RT / IDT)
	if scopes.Contains(oidc.ScopeOpenID) {
		// Generate access token
		at, err := s.generateAccessToken(ctx, client, &tokenv1.TokenMeta{
			Issuer:   req.Issuer,
			Subject:  ar.Subject,
			Audience: ar.Request.Audience,
			Scope:    ar.Request.Scope,
		}, req.TokenConfirmation)
		if err != nil {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to generate access token: %w", err)
		}

		// Check if request has offline_access to generate refresh_token
		if scopes.Contains(oidc.ScopeOfflineAccess) {
			// Generate refresh token
			rt, err := s.generateRefreshToken(ctx, client, &tokenv1.TokenMeta{
				Issuer:   req.Issuer,
				Subject:  ar.Subject,
				Audience: ar.Request.Audience,
				Scope:    ar.Request.Scope,
			}, at.Confirmation)
			if err != nil {
				res.Error = rfcerrors.ServerError().Build()
				return res, fmt.Errorf("unable to generate refresh token: %w", err)
			}

			// Assign response
			res.RefreshToken = rt
		}

		// Assign response
		res.AccessToken = at
	}

	// No error
	return res, nil
}

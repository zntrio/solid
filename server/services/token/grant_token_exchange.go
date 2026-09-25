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
	"errors"
	"fmt"
	"strings"
	"time"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

func (s *service) tokenExchange(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeTokenExchange)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	grant := req.GetTokenExchange()
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// RFC 9396: authorization_details require consent-bound grants; token
	// exchange delegates an existing grant rather than establishing one.
	// Fail closed rather than inventing a consent authority.
	if len(req.AuthorizationDetails) > 0 {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return res, fmt.Errorf("authorization_details is not supported for this grant type")
	}

	// Check subject token
	if grant.SubjectTokenType == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("subject_token_type must not be empty")
	}

	if grant.SubjectToken == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("subject_token must not be empty")
	}

	// Dispatch according to subject_token_type.
	switch grant.SubjectTokenType {
	case oidc.TokenExchangeAccessTokenType:
		err = s.tokenExchangeAccessToken(ctx, client, req, res)
	default:
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("this subject_token_type is invalid or not supported")
	}

	if err != nil {
		return res, fmt.Errorf("unable to process token exchange: %w", err)
	}

	// No error
	return res, nil
}

//nolint:gocyclo,funlen // linear RFC-ordered validation chain; each guard is a protocol requirement
func (s *service) tokenExchangeAccessToken(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest, res *flowv1.TokenResponse) error {
	// Check parameters
	if res == nil {
		return fmt.Errorf("unable to process with nil result")
	}
	if client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to process with nil request")
	}
	grant := req.GetTokenExchange()
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to process with nil grant")
	}

	// Check given token
	st, err := s.tokens.GetByValue(ctx, req.Issuer, grant.SubjectToken)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return fmt.Errorf("unable to retrieve token '%s' from storage: %w", grant.SubjectToken, err)
	}

	// Check token
	if st.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token is not active")
	}
	if st.TokenType != tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token is not an access token")
	}
	if st.Metadata == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("token doesn't have metadata")
	}

	// RFC 8693 section 2.1: only access_token requested_token_type is
	// supported; an explicit other type is an invalid_request.
	if grant.RequestedTokenType != nil && *grant.RequestedTokenType != oidc.TokenExchangeAccessTokenType {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("unsupported requested_token_type '%s'", *grant.RequestedTokenType)
	}

	// RFC 8693 section 2.2.2: when an actor_token is present it MUST be a
	// valid access token issued by this authorization server.
	var actor *tokenv1.Token
	if grant.ActorToken != nil && *grant.ActorToken != "" {
		actor, err = s.tokens.GetByValue(ctx, req.Issuer, *grant.ActorToken)
		if err != nil || actor == nil || actor.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE ||
			actor.TokenType != tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN || actor.Metadata == nil {
			res.Error = rfcerrors.InvalidRequest().Build()
			return fmt.Errorf("actor_token is invalid")
		}
		if actor.Metadata.ExpiresAt < uint64(timeFunc().Unix()) {
			res.Error = rfcerrors.InvalidRequest().Build()
			return fmt.Errorf("actor_token is invalid")
		}

		// RFC 8693 section 5: may_act, when present on the subject token,
		// restricts the allowed actors; an unlisted actor is an
		// invalid_request.
		if len(st.MayAct) > 0 {
			authorized := false
			for _, mayAct := range st.MayAct {
				if mayAct != nil && actor.Metadata != nil && mayAct.Subject == actor.Metadata.Subject {
					authorized = true
					break
				}
			}
			if !authorized {
				res.Error = rfcerrors.InvalidRequest().Build()
				return fmt.Errorf("actor is not authorized to act (may_act)")
			}
		}
	}

	// DPoP confirmation binding: when the subject token is key-bound, the
	// proof presented with this exchange must be made with the same key
	// (prevents proof-key swap during exchange, RFC 9449 section 8).
	if st.Confirmation != nil && st.Confirmation.Jkt != "" {
		if req.TokenConfirmation == nil || !types.SecureCompareString(st.Confirmation.Jkt, req.TokenConfirmation.Jkt) {
			res.Error = rfcerrors.InvalidGrant().Build()
			return fmt.Errorf("token confirmation does not match subject token")
		}
	}

	// If expired
	if st.Metadata.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token is expired")
	}

	// Prepare token metadata: the requested scope MUST NOT exceed the
	// subject token scope (RFC 8693 section 5: the new security token
	// SHOULD NOT be issued with a broader scope than the original).
	scope := st.Metadata.Scope
	if req.Scope != nil && *req.Scope != "" {
		subject := types.StringArray(strings.Fields(st.Metadata.Scope))
		for _, s := range strings.Fields(*req.Scope) {
			if !subject.Contains(s) {
				res.Error = rfcerrors.InvalidScope().Build()
				return fmt.Errorf("requested scope '%s' exceeds subject token scope", *req.Scope)
			}
		}
		scope = *req.Scope
	}

	// Create access token spec
	now := timeFunc()
	at := &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   random.String(jtiLength),
		Metadata: &tokenv1.TokenMeta{
			Issuer:    st.Metadata.Issuer,
			Subject:   st.Metadata.Subject,
			ClientId:  client.ClientId,
			IssuedAt:  uint64(now.Unix()),
			ExpiresAt: uint64(now.Add(1 * time.Minute).Unix()),
			Scope:     scope,
		},
		Confirmation: st.Confirmation,
		Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// RFC 8693 section 4.4: when an actor token was presented, the issued
	// token records the acting party (act chain).
	if actor != nil && actor.Metadata != nil && actor.Metadata.Subject != "" {
		at.Actor = append(at.Actor, &tokenv1.Actor{
			Subject: actor.Metadata.Subject,
		})
		// Preserve any prior act chain carried by the actor token.
		at.Actor = append(at.Actor, actor.Actor...)
	}

	// Add optional meta
	if req.Audience != nil {
		aud, errAud := s.resources.GetByURI(ctx, *req.Audience)
		if errors.Is(errAud, storage.ErrNotFound) {
			res.Error = rfcerrors.InvalidTarget().Build()
			return fmt.Errorf("audience '%s' not found", *req.Audience)
		}
		if errAud != nil {
			return fmt.Errorf("unable to validate audience: %w", errAud)
		}

		// Assign urn
		at.Metadata.Audience = aud.Urn
	}

	// Generate an access token
	at.Value, err = s.accessTokenGen.Generate(ctx, at)
	if err != nil {
		return fmt.Errorf("unable to generate an accessToken: %w", err)
	}

	// Check generator value
	if at.Value == "" {
		return fmt.Errorf("accessTokenGenerator generated an empty value")
	}

	// Store the token spec
	if err := s.tokens.Create(ctx, req.Issuer, at); err != nil {
		return fmt.Errorf("unable to register access token spec in token storage: %w", err)
	}

	// Assign access token
	res.Issuer = st.Metadata.Issuer
	res.AccessToken = at
	res.IssuedTokenType = new(oidc.TokenExchangeAccessTokenType)

	// Assign scope if different
	if st.Metadata.Scope != scope {
		res.Scope = new(scope)
	}

	// No error
	return nil
}

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

// maxActChainDepth caps the total act chain length on exchanged tokens
// (RFC 8693 section 4.4 act chain; policy is server discretion). Deep
// delegation chains are a privilege-laundering vector: every hop is
// another party that may have mis-delegated, and chain resolution cost
// grows linearly. The defensive posture caps the chain at 3 entries —
// immediate actor + at most two prior delegations; deeper chains fail
// closed rather than truncate (silent truncation would misrepresent the
// authorization history to the Resource Server).
const maxActChainDepth = 3

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

	// NOTE: sender-binding policy is not gated here: RFC 8693 exchange
	// requests carry the requester's proof, and the minted token inherits
	// the subject token's confirmation (certificate bindings propagate,
	// RFC 8705 section 3; DPoP key swaps are rejected below at the
	// subject-confirmation comparison).

	// Check subject token
	if grant.SubjectTokenType == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("subject_token_type must not be empty")
	}

	if grant.SubjectToken == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("subject_token must not be empty")
	}

	// Dispatch according to subject_token_type and requested_token_type.
	requestedIDJAG := grant.RequestedTokenType != nil && *grant.RequestedTokenType == oidc.IDJAGTokenType
	if requestedIDJAG {
		// draft-ietf-oauth-identity-assertion-authz-grant-04 section 4.3.
		if errIDJAG := s.tokenExchangeIDJAG(ctx, client, req, res); errIDJAG != nil {
			return res, fmt.Errorf("unable to process ID-JAG token exchange: %w", errIDJAG)
		}
		return res, nil
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
		return fmt.Errorf("unable to retrieve subject token from storage: %w", err)
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
		if actor.Metadata.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
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

	// RFC 8693 section 5 / delegated re-binding: a client listed in the
	// subject token's may_act may re-bind the token to its own key. The
	// may_act list is set exclusively by the AS delegation policy at
	// issuance (WithDelegationPolicy), so a listing represents an explicit
	// authorization for that client to re-delegate. In that case the
	// subject-confirmation equality is replaced by a proof-of-possession
	// requirement: the requesting client MUST present a DPoP proof whose
	// key becomes the new confirmation (verified in the presentation
	// layer before reaching this handler). Security invariant: a stolen
	// subject token fails even with the thief's own valid actor token —
	// not in may_act → strict path → no matching proof → invalid_grant.
	redelegation := actor != nil && mayActContains(client, st)
	if !redelegation {
		// DPoP confirmation binding: when the subject token is key-bound, the
		// proof presented with this exchange must be made with the same key
		// (prevents proof-key swap during exchange, RFC 9449 section 8).
		if st.Confirmation != nil && st.Confirmation.Jkt != "" {
			if req.TokenConfirmation == nil || !types.SecureCompareString(st.Confirmation.Jkt, req.TokenConfirmation.Jkt) {
				res.Error = rfcerrors.InvalidGrant().Build()
				return fmt.Errorf("token confirmation does not match subject token")
			}
		}
	} else if req.TokenConfirmation == nil || req.TokenConfirmation.Jkt == "" {
		// Fail closed: re-delegation without proof of possession of the
		// re-delegating client's key would mint an unbound token.
		res.Error = rfcerrors.InvalidGrant().Build()
		return fmt.Errorf("may_act re-delegation requires a DPoP proof")
	}

	// If expired
	if st.Metadata.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
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

	// Confirmation for the issued token: inherited from the subject token,
	// or re-bound to the requesting client's proof key on an authorized
	// may_act re-delegation.
	confirmation := st.Confirmation
	if redelegation {
		confirmation = &tokenv1.TokenConfirmation{Jkt: req.TokenConfirmation.Jkt}
	}

	// Create access token spec
	now := timeFunc()
	at := &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   random.String(jtiLength),
		Metadata: &tokenv1.TokenMeta{
			Issuer:   st.Metadata.Issuer,
			Subject:  st.Metadata.Subject,
			ClientId: client.ClientId,
			// Grant-family linkage: the exchanged token inherits the subject
			// token's grant id so revokeGrantFamily (RFC 9700 section 4.14.2)
			// reaches derivatives — without it, revoking the source grant
			// leaves the exchanged token alive for its lifetime.
			GrantId:   st.Metadata.GrantId,
			IssuedAt:  uint64(now.Unix()),                      //nolint:gosec // unix time is non-negative
			NotBefore: uint64(now.Unix()),                      //nolint:gosec // unix time is non-negative
			ExpiresAt: uint64(now.Add(1 * time.Minute).Unix()), //nolint:gosec // unix time is non-negative
			Scope:     scope,
			// RFC 9470 section 6: the login authentication event is preserved
			// from the subject token — a delegation keeps the end-user login
			// context so step-up-enforcing resource servers can evaluate the
			// exchanged token.
			Acr:      st.Metadata.Acr,
			AuthTime: st.Metadata.AuthTime,
			// Audience inheritance: absent an explicit audience request the
			// derivative keeps the subject token's audience (RFC 9068
			// section 3 requires a non-blank aud on JWT access tokens).
			Audience: st.Metadata.Audience,
		},
		// Delegated re-binding: a may_act-authorized client re-binds the
		// token to its own key (the DPoP proof presented with this request;
		// possession verified in the presentation layer). Otherwise the
		// subject token's confirmation is inherited verbatim.
		Confirmation: confirmation,
		Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// RFC 8693 section 4.4: the act chain records the delegation history.
	// The issued chain is the immediate actor, then the subject token's
	// chain, then the actor token's prior chain (identity-chaining-17
	// section 2.5: claims transcription must not drop hops — losing the
	// subject's chain would misreport [mcp] instead of [mcp, agent] after
	// the second hop), skipping duplicate subjects, capped by
	// maxActChainDepth.
	if actor != nil && actor.Metadata != nil && actor.Metadata.Subject != "" {
		chain := make([]*tokenv1.Actor, 0, 1+len(st.Actor)+len(actor.Actor))
		seen := map[string]struct{}{actor.Metadata.Subject: {}}
		chain = append(chain, &tokenv1.Actor{Subject: actor.Metadata.Subject})
		for _, source := range [][]*tokenv1.Actor{st.Actor, actor.Actor} {
			for _, entry := range source {
				if entry == nil || entry.Subject == "" {
					continue
				}
				if _, dup := seen[entry.Subject]; dup {
					continue
				}
				seen[entry.Subject] = struct{}{}
				chain = append(chain, entry)
			}
		}
		if len(chain) > maxActChainDepth {
			res.Error = rfcerrors.InvalidRequest().Build()
			return fmt.Errorf("act chain too deep: %d entries exceeds the maximum of %d", len(chain), maxActChainDepth)
		}
		at.Actor = chain
	}

	// Add optional meta. RFC 8693 section 5: the new token's audience MUST
	// NOT exceed the subject token's. Audience retargeting (a token for RS-A
	// exchanged for RS-B) is the delegated-exchange use case: it is only
	// permitted when an actor token proves the delegation — a bearer
	// subject-token exchange cannot silently retarget its audience.
	if req.Audience != nil && actor == nil && st.Metadata.Audience != "" && *req.Audience != st.Metadata.Audience {
		res.Error = rfcerrors.InvalidTarget().Build()
		return fmt.Errorf("audience '%s' exceeds the subject token's audience '%s' (retargeting requires a delegated actor token)", *req.Audience, st.Metadata.Audience)
	}
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

	// may_act issuance (RFC 8693 section 5 / draft-ietf-oauth-identity-
	// chaining section 2.5): when a delegation policy is wired, the token
	// minted for a target resource carries the policy's allow-listed
	// re-delegator client IDs, enabling the next hop's authorized key
	// re-binding. Fail closed: a policy error mints no token. No policy
	// wired → no may_act → re-delegation is impossible anywhere.
	if s.delegationPolicy != nil && req.Audience != nil {
		allowed, errPolicy := s.delegationPolicy.MayRedelegate(ctx, *req.Audience)
		if errPolicy != nil {
			res.Error = rfcerrors.InvalidTarget().Build()
			return fmt.Errorf("delegation policy error for audience '%s': %w", *req.Audience, errPolicy)
		}
		for _, clientID := range allowed {
			if clientID == "" {
				continue
			}
			at.MayAct = append(at.MayAct, &tokenv1.Actor{Subject: clientID})
		}
	}
	if req.AuthorizationDetails != nil {
		// RFC 9396 section 6 / RFC 8693 section 5: the exchanged token's
		// authorization details MUST be a subset of the subject token's
		// consented set — a caller cannot escalate privileges beyond the
		// original grant through exchange (the same rule the
		// authorization-code and refresh grants enforce).
		if errDetails := validateAuthorizationDetailsSubset(req.AuthorizationDetails, st.Metadata.AuthorizationDetails); errDetails != nil {
			res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
			return fmt.Errorf("authorization_details are invalid: %w", errDetails)
		}
		// Assign authorization_details
		at.Metadata.AuthorizationDetails = req.AuthorizationDetails
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

	// RFC 9396 section 7: the granted authorization_details are returned
	// in the token response.
	res.AuthorizationDetails = at.Metadata.AuthorizationDetails

	// Assign scope if different
	if st.Metadata.Scope != scope {
		res.Scope = new(scope)
	}

	// No error
	return nil
}

// mayActContains reports whether the requesting client is listed in the
// subject token's may_act. The comparison is against the client ID (not
// the actor token's subject) because a re-delegating service identifies
// itself through private_key_jwt client authentication: the token it
// re-delegates is presented by its client identity, and the delegation
// policy mints may_act entries as client IDs.
func mayActContains(client *clientv1.Client, st *tokenv1.Token) bool {
	if client == nil || len(st.MayAct) == 0 {
		return false
	}
	for _, mayAct := range st.MayAct {
		if mayAct != nil && mayAct.Subject == client.ClientId {
			return true
		}
	}
	return false
}

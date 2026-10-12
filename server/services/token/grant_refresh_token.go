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

	"google.golang.org/protobuf/proto"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

//nolint:gocyclo,funlen // linear RFC-ordered validation chain; each guard is a protocol requirement
func (s *service) refreshToken(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetRefreshToken()

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeRefreshToken)
	if err != nil {
		res.Error = publicErr
		return res, err
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// NOTE: sender-binding policy is enforced after the stored-confirmation
	// comparison below: an RFC 8705 certificate-bound refresh token fails
	// closed with invalid_grant (proof-of-possession failure), which is the
	// stronger protocol semantics for a stored binding. The policy gate
	// below line 121 covers clients with no stored binding.

	if grant.RefreshToken == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("refresh_token must not be empty")
	}

	// Atomic single-use consume (RFC 9700 section 4.14.2): the presented
	// refresh token transitions ACTIVE -> CONSUMED in one compare-and-set.
	// Concurrent presentations of the same token cannot both win the
	// rotation; the loser observes CONSUMED and is treated as a replay,
	// cascading grant-family revocation exactly like the sequential case.
	rt, err := s.tokens.ConsumeIfActive(ctx, req.Issuer, grant.RefreshToken)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, fmt.Errorf("unable to retrieve refresh token from storage: %w", err)
	}

	// Check the pre-transition state: only the winner of the consume race
	// proceeds with the rotation.
	if rt.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		// RFC 9700 section 4.14.2: replay of an invalidated refresh token
		// reveals theft — revoke the entire grant family. CONSUMED (lost
		// rotation race or sequential replay of a rotated token) and REVOKED
		// both trigger the theft signal.
		if rt.Status != tokenv1.TokenStatus_TOKEN_STATUS_EXPIRED && rt.Metadata != nil && rt.Metadata.GrantId != "" {
			if errRevoke := s.revokeGrantFamily(ctx, req.Issuer, rt.Metadata.GrantId); errRevoke != nil {
				res.Error = rfcerrors.ServerError().Build()
				return res, fmt.Errorf("unable to revoke grant family after refresh token replay: %w", errRevoke)
			}
		}
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("refresh_token in not active")
	}
	if rt.TokenType != tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("refresh_token must be a refresh token")
	}
	if rt.Metadata == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("token doesn't have metadata")
	}

	// If expired
	if rt.Metadata.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("refresh_token is expired")
	}

	// Check client / refresh_token match
	if rt.Metadata.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("only requestor client must use the refresh_token")
	}

	// RFC 8705 section 7.1: refresh tokens minted over mutual TLS are
	// certificate-bound; a refresh request without the matching client
	// certificate thumbprint is a proof-of-possession failure.
	if rt.Confirmation != nil && rt.Confirmation.X5TS256 != "" {
		presented := ""
		if req.TokenConfirmation != nil {
			presented = req.TokenConfirmation.X5TS256
		}
		if presented == "" || !types.SecureCompareString(presented, rt.Confirmation.X5TS256) {
			res.Error = rfcerrors.InvalidGrant().Build()
			return res, fmt.Errorf("refresh token is certificate-bound but no matching x5t#S256 confirmation was presented")
		}
	}

	// RFC 9449 section 8: a DPoP-bound refresh token MUST be refreshed with
	// a proof signed by the same key (jkt continuity); a request under a
	// different key is a proof-of-possession failure, mirroring the x5t
	// branch above and the authorization-code grant's session binding.
	if rt.Confirmation != nil && rt.Confirmation.Jkt != "" {
		presented := ""
		if req.TokenConfirmation != nil {
			presented = req.TokenConfirmation.Jkt
		}
		if presented == "" || !types.SecureCompareString(presented, rt.Confirmation.Jkt) {
			res.Error = rfcerrors.InvalidGrant().Build()
			return res, fmt.Errorf("refresh token is DPoP-bound but no matching jkt confirmation was presented")
		}
	}

	// Sender-constrained token policy (RFC 10027 section 6.1.12 for DPoP,
	// RFC 8705 section 3 for certificate bindings): a client requiring
	// bound access tokens must present its confirmation when no stored
	// binding applies above.
	if errBind := enforceSenderBinding(res, client, req); errBind != nil {
		return res, errBind
	}

	// draft-ietf-oauth-v2-1-16 §4.3.1 (RFC 6749 §6): when the refresh
	// request carries a scope parameter, it MUST NOT exceed the scope
	// granted to the original refresh token; narrowing is permitted.
	// A violation is an invalid_scope.
	if req.Scope != nil && *req.Scope != "" {
		granted := types.StringArray(strings.Fields(rt.Metadata.Scope))
		for _, s := range strings.Fields(*req.Scope) {
			if !granted.Contains(s) {
				res.Error = rfcerrors.InvalidScope().Build()
				return res, fmt.Errorf("requested scope '%s' exceeds refresh token granted scope", *req.Scope)
			}
		}
		// RFC 6749 section 3.3: the requested scope must also stay within
		// the client-registered scope (a client may narrow below its
		// registration but never beyond it, even when the token's grant
		// predates a registration tightening).
		if client.Scope != nil && *client.Scope != "" {
			registered := types.StringArray(strings.Fields(*client.Scope))
			for _, s := range strings.Fields(*req.Scope) {
				if !registered.Contains(s) {
					res.Error = rfcerrors.InvalidScope().Build()
					return res, fmt.Errorf("requested scope '%s' exceeds client registered scope", s)
				}
			}
		}
	}

	// RFC 8707 section 2.2: on a refresh request the acceptable resources
	// are limited to those originally granted (or a subset thereof). With
	// the single-resource posture the only subset of a one-resource grant
	// is the resource itself: a refresh request carrying a resource equal
	// to the granted audience is honored, anything else is an
	// invalid_target.
	if len(req.Resource) > 0 {
		if len(req.Resource) > 1 || req.Resource[0] != rt.Metadata.Audience {
			res.Error = rfcerrors.InvalidTarget().Build()
			return res, fmt.Errorf("requested resource exceeds the resources granted to the refresh token (RFC 8707 section 2.2)")
		}
	}

	// details carried by the refresh token: every requested entry MUST
	// match one entry of the granted set. The narrowed (or unchanged) set
	// is what the rotated tokens carry; the AS never grants more than
	// consented.
	grantedDetails := req.AuthorizationDetails
	if len(grantedDetails) > 0 {
		if errDetails := validateAuthorizationDetailsSubset(req.AuthorizationDetails, rt.Metadata.AuthorizationDetails); errDetails != nil {
			res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
			return res, fmt.Errorf("invalid authorization_details: %w", errDetails)
		}
	} else {
		grantedDetails = rt.Metadata.AuthorizationDetails
	}

	// Generate access token with the effective authorization details and
	// the (possibly narrowed) effective scope.
	narrowedMeta := proto.Clone(rt.Metadata).(*tokenv1.TokenMeta)
	narrowedMeta.AuthorizationDetails = grantedDetails
	if req.Scope != nil && *req.Scope != "" {
		narrowedMeta.Scope = *req.Scope
	}
	at, err := s.generateAccessToken(ctx, client, narrowedMeta, rt.Confirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// Always rotate the refresh token on use: mint a new one and revoke the
	// presented one (RFC 9700 section 4.14.2 refresh token rotation).
	newRt, errRt := s.generateRefreshToken(ctx, client, narrowedMeta, at.Confirmation)
	if errRt != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate refresh token: %w", errRt)
	}

	// The old refresh token was already transitioned to CONSUMED by the
	// atomic ConsumeIfActive above — no separate revoke is needed (the
	// rotation is serialized end-to-end by the compare-and-set).

	// Assign new refresh token
	res.RefreshToken = newRt

	// Assign access token
	res.AccessToken = at
	res.AuthorizationDetails = grantedDetails
	if narrowedMeta.Scope != rt.Metadata.Scope {
		res.Scope = new(narrowedMeta.Scope)
	}

	// No error
	return res, nil
}

// revokeGrantFamily revokes every known token sharing a grant id
// (RFC 9700 section 4.14.2).
func (s *service) revokeGrantFamily(ctx context.Context, issuer, grantID string) error {
	for _, t := range s.tokens.GetByGrantID(ctx, issuer, grantID) {
		if err := s.tokens.Revoke(ctx, issuer, t.TokenId); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("unable to revoke token: %w", err)
		}
	}
	return nil
}

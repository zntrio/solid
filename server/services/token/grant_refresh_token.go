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

	if grant.RefreshToken == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("refresh_token must not be empty")
	}

	// Check given token
	rt, err := s.tokens.GetByValue(ctx, req.Issuer, grant.RefreshToken)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, fmt.Errorf("unable to retrieve token '%s' from storage: %w", grant.RefreshToken, err)
	}

	// Check token
	if rt.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		// RFC 9700 section 4.14.2: replay of an invalidated refresh token
		// reveals theft — revoke the entire grant family.
		if rt.Status == tokenv1.TokenStatus_TOKEN_STATUS_REVOKED && rt.Metadata != nil && rt.Metadata.GrantId != "" {
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

	// RFC 9396 section 6: a refresh request may narrow the authorization
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

	// Generate access token with the effective authorization details.
	narrowedMeta := proto.Clone(rt.Metadata).(*tokenv1.TokenMeta)
	narrowedMeta.AuthorizationDetails = grantedDetails
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

	// Revoke old refresh token
	if errRevoke := s.tokens.Revoke(ctx, req.Issuer, rt.TokenId); errRevoke != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to revoke old refresh token '%s': %w", rt.TokenId, errRevoke)
	}

	// Assign new refresh token
	res.RefreshToken = newRt

	// Assign access token
	res.AccessToken = at
	res.AuthorizationDetails = grantedDetails

	// No error
	return res, nil
}

// revokeGrantFamily revokes every known token sharing a grant id
// (RFC 9700 section 4.14.2).
func (s *service) revokeGrantFamily(ctx context.Context, issuer, grantID string) error {
	for _, t := range s.tokens.GetByGrantID(ctx, issuer, grantID) {
		if err := s.tokens.Revoke(ctx, issuer, t.TokenId); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("unable to revoke token '%s': %w", t.TokenId, err)
		}
	}
	return nil
}

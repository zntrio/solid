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
	"net/url"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
)

//nolint:gocyclo // linear RFC 7009-ordered validation chain; each guard is a protocol requirement
func (s *service) Revoke(ctx context.Context, req *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	res := &tokenv1.RevokeResponse{}

	// Check parameters
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("could not process nil request")
	}
	// Check issuer syntax
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("issuer must not be blank")
	}
	_, err := url.ParseRequestURI(req.Issuer)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("issuer must be a valid url: %w", err)
	}
	if req.Client == nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("no client authentication found")
	}
	if req.Token == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("token parameter is mandatory")
	}

	// Retrieve client information
	_, err = s.clients.Get(ctx, req.Client.ClientId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidClient().Build()
		}
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Retrieve token by value
	t, err := s.tokens.GetByValue(ctx, req.Issuer, req.Token)
	if err != nil {
		// RFC 7009 section 2.2: unknown tokens are revoked silently; the
		// endpoint responds as if the client had submitted an invalid token.
		if errors.Is(err, storage.ErrNotFound) {
			return res, nil
		}
		return res, fmt.Errorf("unable to retrieve token '%s': %w", req.Token, err)
	}

	// RFC 7009 section 2.1: verify the token was issued to the client making
	// the revocation request; refuse otherwise.
	if t.Metadata != nil && t.Metadata.ClientId != req.Client.ClientId {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("token was not issued to client '%s'", req.Client.ClientId)
	}

	// Update token status
	if err := s.tokens.Revoke(ctx, req.Issuer, t.TokenId); err != nil {
		return res, fmt.Errorf("unable to revoke token '%s': %w", t.TokenId, err)
	}

	// RFC 7009 section 2.1: revoking a refresh token revokes the entire
	// grant family — every access token derived from the same grant. The
	// cascade happens after the refresh token itself is revoked so a
	// partial failure leaves the presented token revoked.
	if t.TokenType == tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN && t.Metadata != nil && t.Metadata.GrantId != "" {
		if err := s.revokeGrantFamily(ctx, req.Issuer, t.Metadata.GrantId); err != nil {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to revoke grant family: %w", err)
		}
	}

	// No error
	return res, nil
}

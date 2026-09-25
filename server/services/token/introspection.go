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

//nolint:gocyclo // linear RFC 7662-ordered validation chain; each guard is a protocol requirement
func (s *service) Introspect(ctx context.Context, req *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	res := &tokenv1.IntrospectResponse{}

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

	// Retrieve caller client information
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
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to retrieve to token: %w", err)
	}
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		res.Token = &tokenv1.Token{
			Issuer: req.Issuer,
			Value:  req.Token,
			Status: tokenv1.TokenStatus_TOKEN_STATUS_UNKNOWN,
		}
		return res, nil
	}

	// RFC 7662 section 2.2: a token that has expired MUST be reported as
	// inactive. Map an expired (but still stored) token to the EXPIRED
	// status so the transport layer renders active=false.
	if t.Metadata != nil && t.Metadata.ExpiresAt < uint64(timeFunc().Unix()) && t.Status == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE { //nolint:gosec // unix time is non-negative
		res.Token = &tokenv1.Token{
			Issuer: req.Issuer,
			Value:  req.Token,
			Status: tokenv1.TokenStatus_TOKEN_STATUS_EXPIRED,
		}
		return res, nil
	}
	// RFC 7662 section 2.1: only the token owner and the resource servers
	// it explicitly declared (authorized_introspection_clients) may learn
	// about the token; anyone else gets the same no-cause-distinction
	// envelope as an unknown token.
	if t.Status == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE && t.Metadata != nil && t.Metadata.ClientId != req.Client.ClientId {
		owner, err := s.clients.Get(ctx, t.Metadata.ClientId)
		if err != nil || !containsString(owner.GetAuthorizedIntrospectionClients(), req.Client.ClientId) {
			res.Token = &tokenv1.Token{
				Issuer: req.Issuer,
				Value:  req.Token,
				Status: tokenv1.TokenStatus_TOKEN_STATUS_UNKNOWN,
			}
			return res, nil
		}
	}

	// RFC 7662 section 2.2: an inactive token (revoked, expired, or
	// otherwise not ACTIVE) carries no token claims: the introspection
	// response is the bare inactive envelope, identical for every cause.
	if t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		res.Token = &tokenv1.Token{
			Issuer: req.Issuer,
			Value:  req.Token,
			Status: t.Status,
		}
		return res, nil
	}

	// Return the token
	res.Token = t

	// No error
	return res, nil
}

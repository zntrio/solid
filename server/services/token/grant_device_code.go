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
	"fmt"
	"net/url"
	"strings"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

//nolint:funlen,gocyclo // to refactor
func (s *service) deviceCode(ctx context.Context, client *corev1.Client, req *corev1.TokenRequest) (*corev1.TokenResponse, error) {
	res := &corev1.TokenResponse{}
	grant := req.GetDeviceCode()

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
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeDeviceCode) {
		res.Error = rfcerrors.UnsupportedGrantType().Build()
		return res, fmt.Errorf("client doesn't support '%s' as grant type", oidc.GrantTypeDeviceCode)
	}

	// Validate device_code
	if grant.DeviceCode == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("device_code must not be blank")
	}

	// Resolve device code
	session, err := s.deviceCodeSessions.GetByDeviceCode(ctx, grant.DeviceCode)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}

	// Check session
	if session == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", grant.DeviceCode)
	}
	if session.Request == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has nil request for '%s'", grant.DeviceCode)
	}
	if session.Client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has nil client for '%s'", grant.DeviceCode)
	}

	// Check client match
	if session.Request.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client does not match")
	}

	// Check expiration
	if session.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.TokenExpired().Build()
		return res, fmt.Errorf("token '%s' is expired", grant.DeviceCode)
	}

	// Check if it's validated
	if session.Status == corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING {
		res.Error = rfcerrors.AuthorizationPending().Build()
		return res, fmt.Errorf("token '%s' is waiting for authorization", grant.DeviceCode)
	}

	// Check token state
	if session.Status != corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED {
		res.Error = rfcerrors.InvalidToken().Build()
		return res, fmt.Errorf("token '%s' is invalid", grant.DeviceCode)
	}

	// Check subject attribute
	if session.Subject == "" {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has no subject for '%s'", grant.DeviceCode)
	}

	// Generate access token
	at, err := s.generateAccessToken(ctx, client, &corev1.TokenMeta{
		Issuer:   req.Issuer,
		Scope:    session.Scope,
		Audience: session.Audience,
		Subject:  session.Subject,
	}, req.TokenConfirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// Assign response
	res.AccessToken = at

	// Validate scopes
	scopes := types.StringArray(strings.Fields(session.Scope))

	// Check if request has offline_access to generate refresh_token
	if scopes.Contains(oidc.ScopeOfflineAccess) {
		// Generate refresh token
		rt, err := s.generateRefreshToken(ctx, client, &corev1.TokenMeta{
			Issuer:   req.Issuer,
			Scope:    session.Scope,
			Audience: session.Audience,
			Subject:  session.Subject,
		}, at.Confirmation)
		if err != nil {
			res.AccessToken = nil
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to generate refresh token: %w", err)
		}

		// Assign response
		res.RefreshToken = rt
	}

	// No error
	return res, nil
}

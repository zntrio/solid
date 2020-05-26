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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/types"
)

func (s *service) deviceCode(ctx context.Context, client *corev1.Client, req *corev1.TokenRequest) (*corev1.TokenResponse, error) {
	res := &corev1.TokenResponse{}
	grant := req.GetDeviceCode()

	// Check parameters
	if client == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to process with nil request")
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeDeviceCode) {
		res.Error = rfcerrors.UnsupportedGrantType("")
		return res, fmt.Errorf("client doesn't support '%s' as grant type", oidc.GrantTypeDeviceCode)
	}

	// Validate device_code
	if grant.DeviceCode == "" {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("device_code must not be blank")
	}

	// Resolve device code
	session, err := s.deviceCodeSessions.Get(ctx, grant.DeviceCode)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError("")
		} else {
			res.Error = rfcerrors.InvalidRequest("")
		}
		return res, fmt.Errorf("session is invalid")
	}

	// Check session
	if session == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("retrieved nil session for '%s'", grant.DeviceCode)
	}
	if session.Request == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("session has nil request for '%s'", grant.DeviceCode)
	}
	if session.Client == nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("session has nil client for '%s'", grant.DeviceCode)
	}

	// Check client match
	if session.Request.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("client does not match")
	}

	// Check expiration
	if session.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.TokenExpired()
		return res, fmt.Errorf("token '%s' is expired", grant.DeviceCode)
	}

	// Check if it validated
	if session.Status == corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING {
		res.Error = rfcerrors.AuthorizationPending()
		return res, fmt.Errorf("token '%s' is waiting for authorization", grant.DeviceCode)
	}

	// Check token state
	if session.Status != corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED {
		res.Error = rfcerrors.InvalidToken()
		return res, fmt.Errorf("token '%s' is invalid", grant.DeviceCode)
	}

	// Generate access token
	at, err := s.generateAccessToken(ctx, client, &corev1.TokenMeta{
		Scope:    "",
		Audience: "",
	}, req.TokenConfirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// Assign response
	res.AccessToken = at

	// No error
	return res, nil
}

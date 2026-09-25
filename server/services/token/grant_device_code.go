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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

//nolint:gocyclo,funlen // linear RFC-ordered validation chain; each guard is a protocol requirement
func (s *service) deviceCode(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetDeviceCode()

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeDeviceCode)
	if err != nil {
		res.Error = publicErr
		return res, err
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// RFC 9396 section 3: authorization details were fixed at device
	// authorization time and consented on the session; the token endpoint
	// offers no narrowing for the device grant.
	if len(req.AuthorizationDetails) > 0 {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return res, fmt.Errorf("authorization_details is not supported for this grant type")
	}

	// RFC 10027 section 6.1.12: a client requiring DPoP-bound access
	// tokens must present its proof with every token request; enforced in
	// the transport-agnostic grant, not only at presentation layers.
	if client.DpopBoundAccessTokens && req.TokenConfirmation == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client requires DPoP-bound access tokens")
	}

	// Validate device_code
	if grant.DeviceCode == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("device_code must not be blank")
	}

	// Resolve device code
	session, err := s.deviceCodeSessions.GetByDeviceCode(ctx, req.Issuer, grant.DeviceCode)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
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
	if session.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.TokenExpired().Build()
		return res, fmt.Errorf("token '%s' is expired", grant.DeviceCode)
	}

	// Check if it's pending
	if session.Status == sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING {
		now := timeFunc().Unix()
		interval := session.PollInterval
		if interval < 5 {
			interval = 5 // RFC 8628 section 3.2 default
		}
		if session.LastPolledAt != 0 && now < int64(session.LastPolledAt)+int64(interval) { //nolint:gosec // epoch seconds and small poll interval both fit int64
			// RFC 8628 section 3.5: interval MUST increase by 5 seconds for
			// this and all subsequent requests. LastPolledAt is unchanged, so
			// the next admissible poll is LastPolledAt + new interval.
			session.PollInterval = interval + 5
			if err = s.deviceCodeSessions.UpdateByDeviceCode(ctx, req.Issuer, grant.DeviceCode, session); err != nil {
				res.Error = rfcerrors.ServerError().Build()
				return res, fmt.Errorf("unable to persist poll interval for '%s': %w", grant.DeviceCode, err)
			}
			res.Error = rfcerrors.Slowdown().Build()
			return res, fmt.Errorf("token '%s' is polling too fast", grant.DeviceCode)
		}
		session.LastPolledAt = uint64(now) //nolint:gosec // unix time is non-negative
		if err = s.deviceCodeSessions.UpdateByDeviceCode(ctx, req.Issuer, grant.DeviceCode, session); err != nil {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to persist poll timing for '%s': %w", grant.DeviceCode, err)
		}
		res.Error = rfcerrors.AuthorizationPending().Build()
		return res, fmt.Errorf("token '%s' is waiting for authorization", grant.DeviceCode)
	}

	// RFC 8628 section 3.5: the end user refused the request.
	if session.Status == sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_DENIED {
		res.Error = rfcerrors.AccessDenied().Build()
		return res, fmt.Errorf("authorization request was denied for '%s'", grant.DeviceCode)
	}

	// Check token state
	if session.Status != sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED {
		res.Error = rfcerrors.InvalidToken().Build()
		return res, fmt.Errorf("token '%s' is invalid", grant.DeviceCode)
	}
	// Check subject attribute
	if session.Subject == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has no subject for '%s'", grant.DeviceCode)
	}

	// Atomically consume the validated session (RFC 10027 section 6.1.3,
	// one-time use): after issuance the session is gone, so a later replay
	// hits the unknown-code path above (invalid_request, indistinguishable
	// from unknown — same posture as the authorization-code grant).
	consumed, err := s.deviceCodeSessions.DeleteAndGetByDeviceCode(ctx, req.Issuer, grant.DeviceCode)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Lost a concurrent poll: the code was consumed between read and consume.
			res.Error = rfcerrors.InvalidGrant().Build()
			return res, fmt.Errorf("device code '%s' was already consumed", grant.DeviceCode)
		}
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to consume device code: %w", err)
	}
	session = consumed

	// Prepare token
	tm := &tokenv1.TokenMeta{
		Issuer:  req.Issuer,
		Subject: *session.Subject,
		// Grant family identifier: device-issued tokens must be reachable
		// by grant-family revocation (RFC 9700 section 4.14.2).
		GrantId: random.String(16),
		// RFC 9396 section 3: the consented authorization details ride the
		// session into the minted access token.
		AuthorizationDetails: session.AuthorizationDetails,
	}
	if session.Scope != nil {
		scopes := types.StringArray(strings.Fields(*session.Scope))
		scopes.Remove(oidc.ScopeOfflineAccess) // device flow never grants offline access (RFC 10027 section 6.1.9)
		tm.Scope = strings.Join(scopes, " ")
	}

	// Generate access token (access token only: the device grant never
	// mints refresh tokens — RFC 10027 sections 6.1.9/6.1.10, exfiltrated
	// long-lived refresh tokens are the primary loot of cross-device
	// phishing exploits).
	at, err := s.generateAccessToken(ctx, client, tm, req.TokenConfirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// Assign response
	res.AccessToken = at

	// No error
	return res, nil
}

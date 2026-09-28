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

//nolint:gocyclo,funlen // linear CIBA-section-11-ordered validation chain; each guard is a protocol requirement
func (s *service) ciba(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetCiba()

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeCIBA)
	if err != nil {
		res.Error = publicErr
		return res, err
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// RFC 9396 section 3: authorization details were fixed at backchannel
	// authentication time and consented on the session; the CIBA grant has
	// no token-endpoint narrowing.
	if len(req.AuthorizationDetails) > 0 {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return res, fmt.Errorf("authorization_details is not supported for this grant type")
	}

	// RFC 10027 section 6.1.12: a client requiring DPoP-bound access
	// tokens must present its proof with every token request.
	if client.DpopBoundAccessTokens && req.TokenConfirmation == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client requires DPoP-bound access tokens")
	}

	// Validate auth_req_id
	if grant.AuthReqId == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("auth_req_id must not be blank")
	}

	// Resolve backchannel authentication session
	session, err := s.backchannelSessions.GetByAuthReqID(ctx, req.Issuer, grant.AuthReqId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			// CIBA section 11: an unknown auth_req_id is invalid_grant
			// (unlike RFC 8628).
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}

	// Check session
	if session == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", grant.AuthReqId)
	}
	if session.Request == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has nil request for '%s'", grant.AuthReqId)
	}
	if session.Client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has nil client for '%s'", grant.AuthReqId)
	}

	// Check client match (CIBA section 11: an auth_req_id bound to another
	// client is an invalid auth_req_id for this one -> invalid_grant).
	if session.Request.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("client does not match")
	}

	// RFC 9449 section 10 analog: when the backchannel authentication
	// session is bound to a DPoP key (dpop_jkt declared at bc-authorize
	// time, carried inside the signed request object), the token request
	// MUST prove possession of that same key; anything else is a proof-key
	// swap. The presented thumbprint was verified from the DPoP proof at
	// the transport layer.
	if session.Confirmation != nil && session.Confirmation.Jkt != "" {
		presentedJkt := ""
		if req.TokenConfirmation != nil {
			presentedJkt = req.TokenConfirmation.Jkt
		}
		if presentedJkt == "" {
			res.Error = rfcerrors.InvalidGrant().Build()
			return res, fmt.Errorf("auth_req_id '%s' is bound to a DPoP key but no proof confirmation was presented", grant.AuthReqId)
		}
		if !types.SecureCompareString(session.Confirmation.Jkt, presentedJkt) {
			res.Error = rfcerrors.InvalidGrant().Build()
			return res, fmt.Errorf("DPoP key does not match the auth_req_id binding")
		}
	}
	// Check expiration
	if session.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.TokenExpired().Build()
		return res, fmt.Errorf("auth_req_id '%s' is expired", grant.AuthReqId)
	}

	// Check if it's pending
	if session.Status == sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING {
		now := timeFunc().Unix()
		interval := session.PollInterval
		if interval < 5 {
			interval = 5 // CIBA section 7.3 default
		}
		if session.LastPolledAt != 0 && now < int64(session.LastPolledAt)+int64(interval) { //nolint:gosec // epoch seconds and small poll interval both fit int64
			// CIBA section 11: interval MUST increase by 5 seconds for
			// this and all subsequent requests.
			session.PollInterval = interval + 5
			if err = s.backchannelSessions.UpdateByAuthReqID(ctx, req.Issuer, grant.AuthReqId, session); err != nil {
				res.Error = rfcerrors.ServerError().Build()
				return res, fmt.Errorf("unable to persist poll interval for '%s': %w", grant.AuthReqId, err)
			}
			res.Error = rfcerrors.Slowdown().Build()
			return res, fmt.Errorf("auth_req_id '%s' is polling too fast", grant.AuthReqId)
		}
		session.LastPolledAt = uint64(now) //nolint:gosec // unix time is non-negative
		if err = s.backchannelSessions.UpdateByAuthReqID(ctx, req.Issuer, grant.AuthReqId, session); err != nil {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("unable to persist poll timing for '%s': %w", grant.AuthReqId, err)
		}
		res.Error = rfcerrors.AuthorizationPending().Build()
		return res, fmt.Errorf("auth_req_id '%s' is waiting for end-user approval", grant.AuthReqId)
	}

	// CIBA section 11: the end user refused the request.
	if session.Status == sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_DENIED {
		res.Error = rfcerrors.AccessDenied().Build()
		return res, fmt.Errorf("authorization request was denied for '%s'", grant.AuthReqId)
	}

	// Check token state
	if session.Status != sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED {
		res.Error = rfcerrors.InvalidToken().Build()
		return res, fmt.Errorf("auth_req_id '%s' is invalid", grant.AuthReqId)
	}
	// Check subject attribute
	if session.Subject == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has no subject for '%s'", grant.AuthReqId)
	}

	// Atomically consume the validated session (one-time use): after
	// issuance the session is gone, so a later replay hits the
	// unknown-auth_req_id path above (invalid_grant, CIBA section 11:
	// replay and unknown are deliberately indistinguishable).
	consumed, err := s.backchannelSessions.DeleteAndGetByAuthReqID(ctx, req.Issuer, grant.AuthReqId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Lost a concurrent poll: the session was consumed between
			// read and consume.
			res.Error = rfcerrors.InvalidGrant().Build()
			return res, fmt.Errorf("auth_req_id '%s' was already consumed", grant.AuthReqId)
		}
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to consume auth_req_id: %w", err)
	}
	session = consumed

	// Prepare token
	tm := &tokenv1.TokenMeta{
		Issuer:  req.Issuer,
		Subject: *session.Subject,
		// Grant family identifier: CIBA-issued tokens must be reachable
		// by grant-family revocation (RFC 9700 section 4.14.2).
		GrantId: random.String(16),
		// RFC 9396 section 3: the consented authorization details ride the
		// session into the minted access token.
		AuthorizationDetails: session.AuthorizationDetails,
	}
	if session.Scope != nil {
		scopes := types.StringArray(strings.Fields(*session.Scope))
		scopes.Remove(oidc.ScopeOfflineAccess) // CIBA never grants offline access (RFC 9700 section 4.12.2)
		tm.Scope = strings.Join(scopes, " ")
	}

	// Generate access token (access token only: the CIBA grant never mints
	// refresh tokens — RFC 9700 section 4.12.2, exfiltrated long-lived
	// refresh tokens are the primary loot of cross-device phishing
	// exploits).
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

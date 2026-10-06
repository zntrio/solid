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
	"fmt"
	"net/url"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
)

// validateGrantPreamble applies the validation steps shared by every token
// grant handler: client and request nullity, issuer syntax, and the client
// capability check for the given grant type. When it fails it returns both
// the protocol error to assign to the response and its cause; on success
// both returns are nil and the handler proceeds with grant-specific logic.
func validateGrantPreamble(client *clientv1.Client, req *flowv1.TokenRequest, grantType string) (*corev1.Error, error) {
	// Check parameters
	if client == nil {
		err := rfcerrors.ServerError().Build()
		return err, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		err := rfcerrors.ServerError().Build()
		return err, fmt.Errorf("unable to process with nil request")
	}

	// Check issuer syntax (RFC 6749 section 5.2: malformed client input is
	// an invalid_request, not a server fault).
	if req.Issuer == "" {
		err := rfcerrors.InvalidRequest().Build()
		return err, fmt.Errorf("issuer must not be blank")
	}
	if _, err := url.ParseRequestURI(req.Issuer); err != nil {
		errRes := rfcerrors.InvalidRequest().Build()
		return errRes, fmt.Errorf("issuer must be a valid url: %w", err)
	}

	// Validate client capabilities: the client is authenticated but has no
	// registration for this grant type (RFC 6749 section 5.2:
	// unauthorized_client).
	if !types.StringArray(client.GrantTypes).Contains(grantType) {
		err := rfcerrors.UnauthorizedClient().Build()
		return err, fmt.Errorf("client is not authorized to use grant type '%s'", grantType)
	}
	return nil, nil
}

// enforceSenderBinding enforces the token-binding policy shared by grant
// handlers:
//
//   - the authorization_code grant ALWAYS requires a DPoP confirmation
//     (project security posture: PAR captures dpop_jkt unconditionally,
//     so the code is issued bound to a key and redemption MUST present the
//     matching proof — RFC 9449 section 10);
//   - a client registered with DpopBoundAccessTokens must present a DPoP
//     confirmation for the other grants too (RFC 9449 / RFC 10027 section
//     6.1.12 semantics);
//   - a client registered with TlsClientCertificateBoundAccessTokens must
//     present a mutual-TLS certificate confirmation (RFC 8705 section 3:
//     certificates bound at the token endpoint via x5t#S256).
//
// Grant handlers call this after validateGrantPreamble; the presentation
// layer (HTTP, CoAP) extracts the confirmation from the transport, so the
// mechanism does not depend on any specific presentation.
func enforceSenderBinding(res *flowv1.TokenResponse, client *clientv1.Client, req *flowv1.TokenRequest) error {
	if req.GrantType == oidc.GrantTypeAuthorizationCode && (req.TokenConfirmation == nil || req.TokenConfirmation.Jkt == "") {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("authorization code redemption requires a DPoP confirmation (RFC 9449 section 10)")
	}
	if client.DpopBoundAccessTokens && (req.TokenConfirmation == nil || req.TokenConfirmation.Jkt == "") {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("client requires DPoP-bound access tokens")
	}
	if client.TlsClientCertificateBoundAccessTokens && (req.TokenConfirmation == nil || req.TokenConfirmation.X5TS256 == "") {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("client requires TLS certificate-bound access tokens")
	}
	return nil
}

// minPollInterval is the default poll interval shared by the asynchronous
// grants (RFC 8628 section 3.2; OpenID CIBA Core 1.0 section 7.3).
const minPollInterval = 5

// enforcePollInterval applies the poll-throttling rule shared by the device
// code (RFC 8628 sections 3.2/3.5) and CIBA (OpenID CIBA Core 1.0 sections
// 7.3/11) grants. It reads and mutates the session's PollInterval /
// LastPolledAt pair, persists the mutated session through the persist
// closure, and returns the protocol error: slow_down when the client polls
// faster than the current interval (the interval then MUST increase by 5
// seconds for this and all subsequent requests; LastPolledAt is unchanged so
// the next admissible poll is LastPolledAt + new interval), authorization
// pending when the poll is admissible (LastPolledAt then advances to now).
// A persist failure surfaces as a server_error.
func enforcePollInterval(session pollTiming, persist func() error) (*corev1.Error, error) {
	now := timeFunc().Unix()

	interval := session.getInterval()
	if interval < minPollInterval {
		interval = minPollInterval // RFC 8628 section 3.2 default
	}
	if session.getLast() != 0 && now < session.getLast()+interval {
		// RFC 8628 section 3.5 / CIBA section 11: interval MUST increase
		// by 5 seconds for this and all subsequent requests.
		session.setInterval(interval + minPollInterval)
		if err := persist(); err != nil {
			return rfcerrors.ServerError().Build(), fmt.Errorf("unable to persist poll interval: %w", err)
		}
		return rfcerrors.Slowdown().Build(), fmt.Errorf("polling too fast")
	}

	session.setLast(now)
	if err := persist(); err != nil {
		return rfcerrors.ServerError().Build(), fmt.Errorf("unable to persist poll timing: %w", err)
	}
	return rfcerrors.AuthorizationPending().Build(), nil
}

// pollTiming is the shared poll-throttle accessor pair used by
// enforcePollInterval: the device code (RFC 8628) and CIBA sessions expose
// their PollInterval / LastPolledAt pair through it.
type pollTiming struct {
	getInterval func() int64
	setInterval func(int64)
	getLast     func() int64
	setLast     func(int64)
}

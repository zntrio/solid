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

package clientauthentication

import (
	"time"
)

// assertionClaims is the temporal-claim surface shared by every JWT-profile
// client assertion (RFC 7523 section 3): the per-mechanism claims structs
// embed these fields and delegate their temporal validation to
// validateAssertionTemporal.
type assertionClaims interface {
	issuedAt() uint64
	expiresAt() uint64
	notBefore() uint64
}

// assertionClockSkew is the tolerance applied to assertion temporal
// claims (draft-ietf-oauth-security-topics-update-03 section 2.1.2).
const assertionClockSkew = 5 * time.Minute

// validateAssertionTemporal applies the temporal rules shared by the
// JWT-profile client authentication mechanisms (RFC 7523 section 3,
// draft-ietf-oauth-security-topics-update-03 section 2.1.2):
//
//   - iat must not be in the future (5-minute clock-skew tolerance);
//   - exp must not exceed iat by maxAssertionLifetime;
//   - nbf, when present (> 0), must have elapsed;
//   - exp must be in the future.
//
// The per-mechanism error-code assignment stays at the caller.
func validateAssertionTemporal(claims assertionClaims) error {
	now := uint64(time.Now().Unix()) //nolint:gosec // unix time is non-negative
	// Clock-skew tolerance on iat.
	if claims.issuedAt() > now+uint64(assertionClockSkew.Seconds()) {
		return errAssertionIAFuture
	}
	if claims.expiresAt() > claims.issuedAt()+uint64(maxAssertionLifetime.Seconds()) {
		return errAssertionExpTooFar
	}
	if claims.notBefore() > 0 && claims.notBefore() > now {
		return errAssertionNBFFuture
	}
	if claims.expiresAt() < now {
		return errAssertionExpired
	}
	return nil
}

// Temporal validation errors, shared by the assertion mechanisms; the
// callers wrap them with their protocol error code.
var (
	errAssertionIAFuture  = errAssertion("iat is in the future")
	errAssertionExpTooFar = errAssertion("exp is too far in the future, assertion lifetime must not exceed " + maxAssertionLifetime.String())
	errAssertionNBFFuture = errAssertion("nbf is in the future")
	errAssertionExpired   = errAssertion("expired token")
)

// errAssertion marks temporal validation failures so callers can surface the
// protocol error code while preserving the cause.
type errAssertion string

func (e errAssertion) Error() string { return string(e) }

// validateAudience checks the scalar aud claim of an assertion against the
// authorization server issuer identifier and, when presented, the exact
// receiving endpoint (draft-ietf-oauth-security-topics-update-03 section
// 2.1.2.2: an assertion is accepted only for the endpoint it was sent to,
// or for the issuer identifier).
func validateAudience(aud, issuer, receivingEndpoint string) error {
	if aud != issuer && (receivingEndpoint == "" || aud != receivingEndpoint) {
		return errAssertionAudience
	}
	return nil
}

var errAssertionAudience = errAssertion("aud does not match issuer identifier nor receiving endpoint")

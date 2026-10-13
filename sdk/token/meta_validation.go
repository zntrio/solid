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
	"time"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// ruleTemporalWindow names the iat/nbf/exp constraint set.
const ruleTemporalWindow = "temporal_window"

// validateTokenMeta enforces the shared syntactic constraints of access and
// refresh token meta before claim assembly: required non-blank printable
// audience, subject, client_id and scope, an absolute-URI issuer, and the
// temporal window (iat in [0, now], iat <= nbf <= exp, exp bounded by
// maxLifetime past iat). Failures are returned as *ErrValidation.
func validateTokenMeta(meta *tokenv1.TokenMeta, now uint64, maxLifetime time.Duration) error {
	if meta == nil {
		return fmt.Errorf("token meta must not be nil")
	}
	if err := validatePrintableField(meta.Audience, FieldAudience); err != nil {
		return err
	}
	if err := ValidateURI(meta.Issuer); err != nil {
		return err
	}
	if err := validatePrintableField(meta.Subject, FieldSubject); err != nil {
		return err
	}
	if err := validatePrintableField(meta.ClientId, FieldClientID); err != nil {
		return err
	}
	if err := validatePrintableField(meta.Scope, FieldScope); err != nil {
		return err
	}
	if meta.IssuedAt > now {
		return &ErrValidation{Field: FieldIssuedAt, Rule: ruleTemporalWindow, Reason: "must not be in the future"}
	}
	if meta.NotBefore < meta.IssuedAt || meta.NotBefore > meta.ExpiresAt {
		return &ErrValidation{Field: FieldNotBefore, Rule: ruleTemporalWindow, Reason: "must be within [issued_at, expires_at]"}
	}
	maxExpiration := uint64(time.Unix(int64(meta.IssuedAt), 0).Add(maxLifetime).Unix()) //nolint:gosec // Unix time is non-negative
	if meta.ExpiresAt < meta.IssuedAt || meta.ExpiresAt > maxExpiration {
		return &ErrValidation{Field: FieldExpiresAt, Rule: ruleTemporalWindow, Reason: fmt.Sprintf("must be within [issued_at, iat+%s]", maxLifetime)}
	}
	return nil
}

// validateAssertionMeta enforces the syntactic constraints of a client
// assertion (RFC 7523) meta: the audience is an absolute URI (the AS the
// assertion is presented to), the issuer and subject are printable client
// identifiers, iat is not in the future and exp stays within
// maxLifetime past iat. Unlike access/refresh meta, client_id, scope and
// nbf are not part of an assertion. Failures are *ErrValidation.
func validateAssertionMeta(meta *tokenv1.TokenMeta, now uint64, maxLifetime time.Duration) error {
	if meta == nil {
		return fmt.Errorf("token meta must not be nil")
	}
	if err := ValidateURI(meta.Audience); err != nil {
		return err
	}
	if err := validatePrintableField(meta.Issuer, FieldIssuer); err != nil {
		return err
	}
	if err := validatePrintableField(meta.Subject, FieldSubject); err != nil {
		return err
	}
	if meta.IssuedAt > now {
		return &ErrValidation{Field: FieldIssuedAt, Rule: ruleTemporalWindow, Reason: "must not be in the future"}
	}
	maxExpiration := uint64(time.Unix(int64(meta.IssuedAt), 0).Add(maxLifetime).Unix()) //nolint:gosec // Unix time is non-negative
	if meta.ExpiresAt < meta.IssuedAt || meta.ExpiresAt > maxExpiration {
		return &ErrValidation{Field: FieldExpiresAt, Rule: ruleTemporalWindow, Reason: fmt.Sprintf("must be within [issued_at, iat+%s]", maxLifetime)}
	}
	return nil
}

// validatePrintableField asserts a non-blank printable-ASCII value
// (0x20-0x7E, no control characters).
func validatePrintableField(value string, field ValidationField) error {
	if value == "" {
		return &ErrValidation{Field: field, Rule: "required", Reason: "must not be blank"}
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7E {
			return &ErrValidation{Field: field, Rule: "printable_ascii", Reason: "must be printable ASCII"}
		}
	}
	return nil
}

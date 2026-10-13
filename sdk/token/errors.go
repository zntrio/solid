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
	"errors"
	"fmt"
)

// ErrInvalidTokenSignature is raised when token is signed with a private key
// where the public key is not known by the keyset.
var ErrInvalidTokenSignature = errors.New("invalid token signature")

// ValidationField identifies the token meta field or claim that failed a
// syntactic validation rule.
type ValidationField string

// Validation constraint names reported by ErrValidation.
const (
	FieldAudience  ValidationField = "audience"
	FieldIssuer    ValidationField = "issuer"
	FieldSubject   ValidationField = "subject"
	FieldClientID  ValidationField = "client_id"
	FieldScope     ValidationField = "scope"
	FieldIssuedAt  ValidationField = "issued_at"
	FieldNotBefore ValidationField = "not_before"
	FieldExpiresAt ValidationField = "expires_at"
	FieldURI       ValidationField = "uri"
)

// ErrValidation is the concrete error type returned by token meta and URI
// syntactic validation: callers can branch on the failing field and rule
// with errors.As instead of matching on message text, and compare with
// errors.Is against errValidation for sentinel checks.
type ErrValidation struct {
	// Field is the token meta field or claim key that failed.
	Field ValidationField
	// Rule names the violated constraint (e.g. "required", "printable_ascii",
	// "uri", "temporal_window").
	Rule string
	// Reason is the human-readable constraint description.
	Reason string
}

// Error implements the error interface.
func (e *ErrValidation) Error() string {
	return fmt.Sprintf("%s: %s (%s)", e.Field, e.Reason, e.Rule)
}

// errValidation is the sentinel matched by errors.Is(err, ErrValidation{}).
var errValidation = errors.New("invalid token metadata")

// Is reports the sentinel identity so errors.Is(err, errValidation) matches
// any ErrValidation while the concrete value stays inspectable with errors.As.
func (e *ErrValidation) Is(target error) bool {
	return target == errValidation
}

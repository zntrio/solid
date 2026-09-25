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

// Package authzdetails provides building blocks for RFC 9396 Rich
// Authorization Requests: semantic validation of the authorization_details
// entries carried by an authorization request.
package authzdetails

import (
	"context"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// ValidatorFunc adapts a plain function to the Validator interface.
type ValidatorFunc func(ctx context.Context, details []*tokenv1.AuthorizationDetail) error

// Validate implements Validator.
func (f ValidatorFunc) Validate(ctx context.Context, details []*tokenv1.AuthorizationDetail) error {
	return f(ctx, details)
}

// Validator checks the semantic validity of requested authorization details
// (RFC 9396 sections 2 and 5): known type, conformance to the type
// definition, field validity. It is invoked only when the authorization
// request carries at least one detail; a nil Validator rejects every
// non-empty detail set (fail-closed default).
type Validator interface {
	Validate(ctx context.Context, details []*tokenv1.AuthorizationDetail) error
}

// TypesSupported advertises the supported type identifiers for the
// authorization_details_types_supported server metadata value
// (RFC 9396 section 10).
type TypesSupported []string

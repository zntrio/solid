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

package authzdetails

import (
	"context"
	"fmt"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// StaticValidator validates authorization details against a static registry
// of supported type identifiers: every requested detail carries a type the
// authorization server knows (RFC 9396 section 5: an unsupported type MUST
// be rejected). Deep type-schema validation (per-type allowed actions,
// extension fields) is deployment-specific and layered on top by consumers.
type StaticValidator struct {
	supported map[string]struct{}
}

// NewStaticValidator builds a StaticValidator over the given supported type
// identifiers. The map must not be mutated after construction.
func NewStaticValidator(supported map[string]struct{}) *StaticValidator {
	return &StaticValidator{supported: supported}
}

// Validate implements Validator: it fails when a requested detail carries a
// type that is not registered.
func (v *StaticValidator) Validate(_ context.Context, details []*tokenv1.AuthorizationDetail) error {
	if v == nil {
		return fmt.Errorf("authorization details validator is not configured")
	}
	for i, detail := range details {
		if detail == nil {
			return fmt.Errorf("authorization_details[%d]: entry must not be null", i)
		}
		if _, ok := v.supported[detail.Type]; !ok {
			return fmt.Errorf("authorization_details[%d]: unsupported type %q", i, detail.Type)
		}
	}
	return nil
}

// TypesSupported implements Validator exposure of the registry: it returns the
// advertised type identifiers for the server metadata (RFC 9396 section 10).
func (v *StaticValidator) TypesSupported() TypesSupported {
	if v == nil || len(v.supported) == 0 {
		return nil
	}
	types := make(TypesSupported, 0, len(v.supported))
	for t := range v.supported {
		types = append(types, t)
	}
	return types
}

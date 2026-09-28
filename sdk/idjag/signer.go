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

package idjag

import (
	"context"
	"errors"
	"fmt"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/token"
)

// DefaultSigner builds an ID-JAG signer from a claims serializer
// (token.Serializer), e.g. jwt.IDJAG, a CWT signer or a PASETO signer
// assembled by the consumer. The serialization format is the assembly's
// decision; this package stays agnostic.
func DefaultSigner(serializer token.Serializer) Signer {
	return &defaultSigner{
		delegate: serializer,
	}
}

type defaultSigner struct {
	delegate token.Serializer
}

// Serialize validates the REQUIRED claim set (draft section 3.1) and signs
// the ID-JAG. Missing or empty REQUIRED claims fail closed.
func (s *defaultSigner) Serialize(ctx context.Context, grant *tokenv1.IdentityAssertionJWTAuthorizationGrant) (string, error) {
	// Check arguments
	if grant == nil {
		return "", errors.New("unable to sign a nil ID-JAG")
	}

	// Enforce REQUIRED claims (draft section 3.1). Optional claims are
	// skipped by omitempty semantics of the JSON marshaller.
	if grant.Iss == "" {
		return "", errors.New("ID-JAG iss claim is required")
	}
	if grant.Sub == "" {
		return "", errors.New("ID-JAG sub claim is required")
	}
	if grant.Aud == "" {
		return "", errors.New("ID-JAG aud claim is required")
	}
	if grant.ClientId == "" {
		return "", errors.New("ID-JAG client_id claim is required")
	}
	if grant.Jti == "" {
		return "", errors.New("ID-JAG jti claim is required")
	}
	if grant.Exp == 0 {
		return "", errors.New("ID-JAG exp claim is required")
	}
	if grant.Iat == 0 {
		return "", errors.New("ID-JAG iat claim is required")
	}

	// Check serializer
	if s.delegate == nil {
		return "", errors.New("unable to sign with a nil serializer")
	}

	// Serialize through the injected serializer.
	raw, err := s.delegate.Serialize(ctx, grant)
	if err != nil {
		return "", fmt.Errorf("unable to serialize ID-JAG: %w", err)
	}

	// No error
	return raw, nil
}

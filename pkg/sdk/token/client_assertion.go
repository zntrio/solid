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
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/types"
)

// -----------------------------------------------------------------------------

// ClientAssertion instantiate a client assertion generator.
func ClientAssertion(signer Signer) Generator {
	return &clientAssertionGenerator{
		signer: signer,
	}
}

// -----------------------------------------------------------------------------

type clientAssertionGenerator struct {
	signer Signer
}

func (c *clientAssertionGenerator) Generate(ctx context.Context, t *corev1.Token) (string, error) {
	// Check arguments
	if types.IsNil(c.signer) {
		return "", fmt.Errorf("unable to use nil signer")
	}
	if t == nil {
		return "", fmt.Errorf("unable to generate claims from nil token")
	}
	if t.TokenId == "" {
		return "", fmt.Errorf("token id must not be blank")
	}
	if t.Metadata == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// Validate meta informations
	if err := c.validateMeta(t.Metadata); err != nil {
		return "", fmt.Errorf("unable to generate claims, invalid meta: %w", err)
	}

	// Prepare claims
	claims := map[string]interface{}{
		"iss": t.Metadata.Issuer,
		"iat": t.Metadata.IssuedAt,
		"exp": t.Metadata.ExpiresAt,
		"sub": t.Metadata.Subject,
		"aud": t.Metadata.Audience,
		"jti": t.TokenId,
	}

	// Sign the assertion
	raw, err := c.signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign client assertion: %w", err)
	}

	// No error
	return raw, nil
}

// -----------------------------------------------------------------------------

func (c *clientAssertionGenerator) validateMeta(meta *corev1.TokenMeta) error {
	// Check arguments
	if meta == nil {
		return fmt.Errorf("token meta must not be nil")
	}

	now := uint64(time.Now().Unix())
	maxExpiration := uint64(time.Unix(int64(meta.IssuedAt), 0).Add(2 * time.Hour).Unix())

	// Validate syntaxically
	if err := validation.ValidateStruct(meta,
		validation.Field(&meta.Audience, validation.Required, is.URL),
		validation.Field(&meta.Issuer, validation.Required, is.PrintableASCII),
		validation.Field(&meta.Subject, validation.Required, is.PrintableASCII),
		validation.Field(&meta.IssuedAt, validation.Required, validation.Min(uint64(0)), validation.Max(now)),
		validation.Field(&meta.ExpiresAt, validation.Required, validation.Min(meta.IssuedAt), validation.Max(maxExpiration)),
	); err != nil {
		return fmt.Errorf("unable to validate claims: %w", err)
	}

	// Constraints
	if meta.Subject != meta.Issuer {
		return errors.New("subject and issuer must be identic")
	}

	// No error
	return nil
}

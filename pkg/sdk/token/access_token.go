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
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/types"
)

// -----------------------------------------------------------------------------

// AccessToken instantiate an access token generator.
func AccessToken(signer Signer) Generator {
	return &accessTokenGenerator{
		signer: signer,
	}
}

// -----------------------------------------------------------------------------

type accessTokenGenerator struct {
	signer Signer
}

func (c *accessTokenGenerator) Generate(ctx context.Context, jti string, meta *corev1.TokenMeta, cnf *corev1.TokenConfirmation) (string, error) {
	// Check arguments
	if types.IsNil(c.signer) {
		return "", fmt.Errorf("unable to use nil signer")
	}
	if jti == "" {
		return "", fmt.Errorf("token id must not be blank")
	}
	if meta == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// Validate meta informations
	if err := c.validateMeta(meta); err != nil {
		return "", fmt.Errorf("unable to generate claims, invalid meta: %w", err)
	}

	// Prepare claims
	claims := map[string]interface{}{
		"iss":       meta.Issuer,
		"exp":       meta.ExpiresAt,
		"aud":       meta.Audience,
		"iat":       meta.IssuedAt,
		"nbf":       meta.NotBefore,
		"sub":       meta.Subject,
		"client_id": meta.ClientId,
		"jti":       jti,
		"scope":     meta.Scope,
	}

	// If token has a confirmation
	if cnf != nil {
		// Add jwt key token proof
		claims["cnf"] = map[string]interface{}{
			"jkt": cnf.Jkt,
		}
	}

	// Sign the assertion
	raw, err := c.signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	// No error
	return raw, nil
}

// -----------------------------------------------------------------------------

func (c *accessTokenGenerator) validateMeta(meta *corev1.TokenMeta) error {
	// Check arguments
	if meta == nil {
		return fmt.Errorf("token meta must not be nil")
	}

	now := uint64(time.Now().Unix())
	maxExpiration := uint64(time.Unix(int64(meta.IssuedAt), 0).Add(2 * time.Hour).Unix())

	// Validate syntaxically
	if err := validation.ValidateStruct(meta,
		validation.Field(&meta.Audience, validation.Required, is.PrintableASCII),
		validation.Field(&meta.Issuer, validation.Required, is.URL),
		validation.Field(&meta.Subject, validation.Required, is.PrintableASCII),
		validation.Field(&meta.IssuedAt, validation.Required, validation.Min(uint64(0)), validation.Max(now)),
		validation.Field(&meta.NotBefore, validation.Required, validation.Min(meta.IssuedAt), validation.Max(meta.ExpiresAt)),
		validation.Field(&meta.ExpiresAt, validation.Required, validation.Min(meta.IssuedAt), validation.Max(maxExpiration)),
	); err != nil {
		return fmt.Errorf("unable to validate claims: %w", err)
	}

	// No error
	return nil
}

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
	"zntr.io/solid/sdk/types"
)

// -----------------------------------------------------------------------------

// RefreshToken instantiate an refresh token generator.
func RefreshToken(signer Serializer) Generator {
	return &refreshTokenGenerator{
		signer: signer,
	}
}

// -----------------------------------------------------------------------------

type refreshTokenGenerator struct {
	signer Serializer
}

func (c *refreshTokenGenerator) Generate(ctx context.Context, t *corev1.Token) (string, error) {
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
	claims := struct {
		Iss      string                    `json:"iss,omitempty" cbor:"1,keyasint,omitempty"`
		Sub      string                    `json:"sub,omitempty" cbor:"2,keyasint,omitempty"`
		Aud      string                    `json:"aud,omitempty" cbor:"3,keyasint,omitempty"`
		Exp      uint64                    `json:"exp,omitempty" cbor:"4,keyasint,omitempty"`
		Nbf      uint64                    `json:"nbf,omitempty" cbor:"5,keyasint,omitempty"`
		Iat      uint64                    `json:"iat,omitempty" cbor:"6,keyasint,omitempty"`
		JTI      string                    `json:"jti,omitempty" cbor:"7,keyasint,omitempty"`
		ClientID string                    `json:"client_id,omitempty" cbor:"100,keyasint,omitempty"`
		Scope    string                    `json:"scope,omitempty" cbor:"101,keyasint,omitempty"`
		Cnf      *corev1.TokenConfirmation `json:"cnf,omitempty" cbor:"102,keyasint,omitempty"`
	}{
		Iss:      t.Metadata.Issuer,
		Sub:      t.Metadata.Subject,
		Aud:      t.Metadata.Audience,
		Exp:      t.Metadata.ExpiresAt,
		Nbf:      t.Metadata.NotBefore,
		Iat:      t.Metadata.IssuedAt,
		JTI:      t.TokenId,
		ClientID: t.Metadata.ClientId,
		Scope:    t.Metadata.Scope,
	}

	// Sign the assertion
	raw, err := c.signer.Serialize(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	// No error
	return raw, nil
}

// -----------------------------------------------------------------------------

func (c *refreshTokenGenerator) validateMeta(meta *corev1.TokenMeta) error {
	// Check arguments
	if meta == nil {
		return fmt.Errorf("token meta must not be nil")
	}

	now := uint64(time.Now().Unix())
	maxExpiration := uint64(time.Unix(int64(meta.IssuedAt), 0).Add(14 * 24 * time.Hour).Unix())

	// Validate syntaxically
	if err := validation.ValidateStruct(meta,
		validation.Field(&meta.Audience, validation.Required, is.PrintableASCII),
		validation.Field(&meta.Issuer, validation.Required, is.URL),
		validation.Field(&meta.Subject, validation.Required, is.PrintableASCII),
		validation.Field(&meta.ClientId, validation.Required, is.PrintableASCII),
		validation.Field(&meta.Scope, validation.Required, is.PrintableASCII),
		validation.Field(&meta.IssuedAt, validation.Required, validation.Min(uint64(0)), validation.Max(now)),
		validation.Field(&meta.NotBefore, validation.Required, validation.Min(meta.IssuedAt), validation.Max(meta.ExpiresAt)),
		validation.Field(&meta.ExpiresAt, validation.Required, validation.Min(meta.IssuedAt), validation.Max(maxExpiration)),
	); err != nil {
		return fmt.Errorf("unable to validate claims: %w", err)
	}

	// No error
	return nil
}

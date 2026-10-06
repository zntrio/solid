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

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/types"
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

func (c *accessTokenGenerator) Generate(ctx context.Context, t *tokenv1.Token) (string, error) {
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
	claims := assembleAccessTokenClaims(t)

	// Sign the assertion
	raw, err := c.signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	// No error
	return raw, nil
}

// assembleAccessTokenClaims builds the claim object of an access token
// from its persisted spec: the RFC 9068 protocol claims plus cnf when
// confirmed (shared by the plain and the selectively disclosable
// generators).
func assembleAccessTokenClaims(t *tokenv1.Token) any {
	claims := struct {
		Iss                  string                         `json:"iss,omitempty" cbor:"1,keyasint,omitempty"`
		Sub                  string                         `json:"sub,omitempty" cbor:"2,keyasint,omitempty"`
		Aud                  string                         `json:"aud,omitempty" cbor:"3,keyasint,omitempty"`
		Exp                  uint64                         `json:"exp,omitempty" cbor:"4,keyasint,omitempty"`
		Nbf                  uint64                         `json:"nbf,omitempty" cbor:"5,keyasint,omitempty"`
		Iat                  uint64                         `json:"iat,omitempty" cbor:"6,keyasint,omitempty"`
		JTI                  string                         `json:"jti,omitempty" cbor:"7,keyasint,omitempty"`
		ClientID             string                         `json:"client_id,omitempty" cbor:"100,keyasint,omitempty"`
		Scope                string                         `json:"scope,omitempty" cbor:"101,keyasint,omitempty"`
		Cnf                  *JSONConfirmation              `json:"cnf,omitempty" cbor:"102,keyasint,omitempty"`
		AuthorizationDetails []*tokenv1.AuthorizationDetail `json:"authorization_details,omitempty" cbor:"103,keyasint,omitempty"`
		ACR                  string                         `json:"acr,omitempty" cbor:"104,keyasint,omitempty"`
		AuthTime             uint64                         `json:"auth_time,omitempty" cbor:"105,keyasint,omitempty"`
	}{
		Iss:                  t.Metadata.Issuer,
		Sub:                  t.Metadata.Subject,
		Aud:                  t.Metadata.Audience,
		Exp:                  t.Metadata.ExpiresAt,
		Nbf:                  t.Metadata.NotBefore,
		Iat:                  t.Metadata.IssuedAt,
		JTI:                  t.TokenId,
		ClientID:             t.Metadata.ClientId,
		Scope:                t.Metadata.Scope,
		AuthorizationDetails: t.Metadata.AuthorizationDetails,
		// RFC 9470 section 6.1: authentication event claims of the login.
		ACR:      t.Metadata.GetAcr(),
		AuthTime: t.Metadata.GetAuthTime(),
	}

	// If token has a confirmation
	if t.Confirmation != nil {
		// Add jwt key token proof with RFC-mandated member names
		claims.Cnf = ConfirmationAsJSON(t.Confirmation)
	}

	return claims
}

// -----------------------------------------------------------------------------

func (c *accessTokenGenerator) validateMeta(meta *tokenv1.TokenMeta) error {
	// Check arguments
	if meta == nil {
		return fmt.Errorf("token meta must not be nil")
	}

	now := uint64(time.Now().Unix())                                                      //nolint:gosec // Unix time is non-negative
	maxExpiration := uint64(time.Unix(int64(meta.IssuedAt), 0).Add(2 * time.Hour).Unix()) //nolint:gosec // Unix time is non-negative

	// Validate syntaxically
	if err := validation.ValidateStruct(meta,
		validation.Field(&meta.Audience, validation.Required, is.PrintableASCII),
		validation.Field(&meta.Issuer, validation.Required, ValidateURI),
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

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

package paseto

import (
	"context"
	"fmt"
	"time"

	pasetolib "github.com/o1egl/paseto"
	"github.com/square/go-jose"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/generator"
	"zntr.io/solid/pkg/sdk/jwk"
)

// -----------------------------------------------------------------------------

// AccessToken instantiate a PASETO access token generator.
func AccessToken(keyProvider jwk.KeyProviderFunc) generator.Token {
	return &accessTokenGenerator{
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

// KeyProviderFunc defines key provider contract.
type KeyProviderFunc func() (*jose.JSONWebKey, error)

type accessTokenGenerator struct {
	keyProvider jwk.KeyProviderFunc
}

func (c *accessTokenGenerator) Generate(ctx context.Context, jti string, meta *corev1.TokenMeta, cnf *corev1.TokenConfirmation) (string, error) {
	// Check arguments
	if c.keyProvider == nil {
		return "", fmt.Errorf("unable to use nil key provider")
	}
	if jti == "" {
		return "", fmt.Errorf("token id must not be blank")
	}
	if meta == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// Retrieve signing key
	key, err := c.keyProvider(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve a signing key: %w", err)
	}

	// Check
	if key == nil {
		return "", fmt.Errorf("key provider returned a nil key")
	}
	if key.KeyID == "" {
		return "", fmt.Errorf("key provider returned a unidentifiable key")
	}

	// Prepare claims
	claims := pasetolib.JSONToken{
		Audience:   meta.Audience,
		Expiration: time.Unix(int64(meta.ExpiresAt), 0),
		IssuedAt:   time.Unix(int64(meta.IssuedAt), 0),
		Issuer:     meta.Issuer,
		Jti:        jti,
		NotBefore:  time.Unix(int64(meta.IssuedAt), 0),
		Subject:    meta.Subject,
	}

	// Add custom claim
	claims.Set("client_id", meta.ClientId)
	claims.Set("scope", meta.Scope)

	// If token has a confirmation
	if cnf != nil {
		// Add jwt key token proof
		claims.Set("cnf", fmt.Sprintf(`{"jkt": "%s"}`, cnf.Jkt))
	}

	token, err := pasetolib.NewV2().Sign(key.Key, &claims, key.KeyID)
	if err != nil {
		return "", fmt.Errorf("unable to sign paseto access token: %w", err)
	}

	// No error
	return token, nil
}

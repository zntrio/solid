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

package jwt

import (
	"context"
	"fmt"

	"go.zenithar.org/solid/pkg/generator"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"

	"github.com/square/go-jose/v3"
	jwt "github.com/square/go-jose/v3/jwt"
)

// -----------------------------------------------------------------------------

// AccessToken instanciate a JWT access token generator.
func AccessToken(alg jose.SignatureAlgorithm, keyProvider KeyProviderFunc) generator.Token {
	return &accessTokenGenerator{
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

// KeyProviderFunc defines key provider contract.
type KeyProviderFunc func() (*jose.JSONWebKey, error)

type accessTokenGenerator struct {
	alg         jose.SignatureAlgorithm
	keyProvider KeyProviderFunc
}

func (c *accessTokenGenerator) Generate(ctx context.Context, jti string, meta *corev1.TokenMeta) (string, error) {
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
	key, err := c.keyProvider()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve a signing key: %w", err)
	}

	// Check
	if key == nil {
		return "", fmt.Errorf("key provider returned a nil key")
	}

	// Preapre JWT header
	options := (&jose.SignerOptions{}).WithType("at+JWT")
	options = options.WithHeader(jose.HeaderKey("kid"), key.KeyID)

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: c.alg, Key: key}, options)
	if err != nil {
		return "", fmt.Errorf("unable to prepare signer: %w", err)
	}

	// Sign the assertion
	raw, err := jwt.Signed(sig).Claims(map[string]interface{}{
		"iss":   meta.Issuer,
		"exp":   meta.ExpiresAt,
		"aud":   meta.Audience,
		"iat":   meta.IssuedAt,
		"sub":   meta.ClientId,
		"jti":   jti,
		"scope": meta.Scope,
	}).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to sign client assertion: %w", err)
	}

	// No error
	return raw, nil
}

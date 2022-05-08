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
	"errors"
	"fmt"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/types"
)

type defaultSigner struct {
	tokenType   string
	alg         jose.SignatureAlgorithm
	keyProvider jwk.KeyProviderFunc
	embedJWK    bool
}

func (ds *defaultSigner) Serialize(ctx context.Context, claims any) (string, error) {
	// Check arguments
	if types.IsNil(claims) {
		return "", errors.New("unable to sign nil claim object")
	}
	if ds.keyProvider == nil {
		return "", errors.New("unable to use nil keyProvider")
	}

	// Retrieve signing key
	key, err := ds.keyProvider(ctx)
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
	// Prepare JWT header
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(ds.tokenType))
	options = options.WithHeader(jose.HeaderKey("kid"), key.KeyID)
	options.EmbedJWK = ds.embedJWK

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: ds.alg, Key: key}, options)
	if err != nil {
		return "", fmt.Errorf("unable to prepare signer: %w", err)
	}

	// Generate the final proof
	raw, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to generate JWT: %w", err)
	}

	// No error
	return raw, nil
}

func (ds *defaultSigner) ContentType() string {
	return "JWT"
}

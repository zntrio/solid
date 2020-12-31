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
	"errors"
	"fmt"

	pasetolib "github.com/o1egl/paseto"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/sdk/types"
)

// DefaultSigner declare a default PASETO signer.
func DefaultSigner(tokenType string, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   fmt.Sprintf("%s+paseto", tokenType),
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

type defaultSigner struct {
	tokenType   string
	keyProvider jwk.KeyProviderFunc
}

func (ds *defaultSigner) Sign(ctx context.Context, claims interface{}) (string, error) {
	// Check arguments
	if types.IsNil(claims) {
		return "", errors.New("unable to sign nil claim object")
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

	// Prepare footer
	footer := map[string]string{
		"kid": key.KeyID,
		"typ": ds.tokenType,
	}

	// Prepare a signer
	raw, err := pasetolib.NewV2().Sign(key.Key, claims, footer)
	if err != nil {
		return "", fmt.Errorf("unable to sign paseto token: %w", err)
	}

	// No error
	return raw, nil
}

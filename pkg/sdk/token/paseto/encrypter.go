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
)

// Encrypter returns a token encrypter service.
func Encrypter(encryptionKeyProviderFunc jwk.KeyProviderFunc) token.Encrypter {
	return &defaultEncrypter{
		encryptionKeyProvider: encryptionKeyProviderFunc,
	}
}

// -----------------------------------------------------------------------------

type defaultEncrypter struct {
	encryptionKeyProvider jwk.KeyProviderFunc
}

func (ds *defaultEncrypter) Encrypt(ctx context.Context, tokenType, token string, aad []byte) (string, error) {
	// Check arguments
	if ds.encryptionKeyProvider == nil {
		return "", errors.New("unable to use nil encryptionKeyProvider")
	}

	// Retrieve encryption key
	encryptionKey, err := ds.encryptionKeyProvider(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve an encryption key: %w", err)
	}

	// Check
	if encryptionKey == nil {
		return "", fmt.Errorf("encryptionKey provider returned a nil key")
	}
	if encryptionKey.KeyID == "" {
		return "", fmt.Errorf("encryptionKey provider returned an unidentifiable key")
	}
	rawKey, ok := encryptionKey.Key.([]byte)
	if !ok {
		return "", fmt.Errorf("encryptionKey provider returned an invalid key type: %T", encryptionKey.Key)
	}

	// Prepare a signer
	raw, err := pasetolib.NewV2().Encrypt(rawKey, token, aad)
	if err != nil {
		return "", fmt.Errorf("unable to sign paseto token: %w", err)
	}

	// No error
	return raw, nil
}

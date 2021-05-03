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

	"github.com/square/go-jose/v3"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// Encrypter returns a token encrypter service.
func Encrypter(keyAlgorithm jose.KeyAlgorithm, encryptionMethod jose.ContentEncryption, encryptionKeyProviderFunc jwk.KeyProviderFunc) token.Encrypter {
	return &defaultEncrypter{
		keyAlgorithm:          keyAlgorithm,
		encryptionMethod:      encryptionMethod,
		encryptionKeyProvider: encryptionKeyProviderFunc,
	}
}

// -----------------------------------------------------------------------------

type defaultEncrypter struct {
	keyAlgorithm          jose.KeyAlgorithm
	encryptionMethod      jose.ContentEncryption
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
		return "", fmt.Errorf("encryptionKey provider returned a unidentifiable key")
	}

	// Prepare an encrypter
	encrypter, err := jose.NewEncrypter(ds.encryptionMethod, jose.Recipient{
		Algorithm: ds.keyAlgorithm,
		Key:       encryptionKey.Key,
		KeyID:     encryptionKey.KeyID,
	}, &jose.EncrypterOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderContentType: jose.ContentType(tokenType),
		},
	})
	if err != nil {
		return "", fmt.Errorf("unable to prepare token encrypter: %w", err)
	}

	// Encrypt input token
	var wrapped *jose.JSONWebEncryption
	if aad == nil {
		wrapped, err = encrypter.Encrypt([]byte(token))
	} else {
		wrapped, err = encrypter.EncryptWithAuthData([]byte(token), aad)
	}

	// Generate the final proof
	raw, err := wrapped.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to generate JWE: %w", err)
	}

	// No error
	return raw, nil
}

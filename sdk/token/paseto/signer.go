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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	pasetov4 "zntr.io/paseto/v4"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
)

// DefaultSigner declare a default PASETO signer.
func DefaultSigner(tokenType string, keyProvider jwk.KeyProviderFunc) token.Serializer {
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
	keyRaw, ok := key.Key.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key provider returned an invalid key type")
	}

	// Prepare footer
	footer := map[string]string{
		"kid": key.KeyID,
		"typ": ds.tokenType,
	}

	// Encode claims
	m := bytes.Buffer{}
	if err := json.NewEncoder(&m).Encode(claims); err != nil {
		return "", fmt.Errorf("unable to encode message payload: %w", err)
	}

	// Encode footer
	f := bytes.Buffer{}
	if err := json.NewEncoder(&f).Encode(footer); err != nil {
		return "", fmt.Errorf("unable to encode token footer: %w", err)
	}

	// Sign with paseto v4
	raw, err := pasetov4.Sign(m.Bytes(), keyRaw, f.String(), "")
	if err != nil {
		return "", fmt.Errorf("unable to sign paseto token: %w", err)
	}

	// No error
	return string(raw), nil
}

func (ds *defaultSigner) ContentType() string {
	return "PASETO"
}

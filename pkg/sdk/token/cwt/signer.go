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

package cwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	"go.mozilla.org/cose"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/sdk/types"
)

// DefaultSigner declare a default CWT signer.
func DefaultSigner(tokenType string, alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   fmt.Sprintf("%s+cwt", tokenType),
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

type defaultSigner struct {
	tokenType   string
	alg         *cose.Algorithm
	keyProvider jwk.KeyProviderFunc
}

func (ds *defaultSigner) Serialize(ctx context.Context, claims interface{}) (string, error) {
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
	if key.IsPublic() {
		return "", fmt.Errorf("key provider returned a public key which is unusable for signing purpose")
	}

	// Prepare signer
	signer, err := cose.NewSignerFromKey(ds.alg, key.Key)
	if err != nil {
		return "", fmt.Errorf("unable to initialize COSE signer: %w", err)
	}

	sig := cose.NewSignature()
	sig.Headers.Unprotected["kid"] = key.KeyID
	sig.Headers.Protected["typ"] = fmt.Sprintf("%s+cwt", ds.tokenType)
	sig.Headers.Protected["alg"] = ds.alg.Name

	// Prepare claims
	b, err := cbor.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("unable to serialize claims as CBOR: %w", err)
	}

	// Assemble final assertion
	msg := cose.NewSignMessage()
	msg.Payload = b
	msg.AddSignature(sig)

	// Sign assertion
	if err := msg.Sign(rand.Reader, []byte("solid"), []cose.Signer{*signer}); err != nil {
		return "", fmt.Errorf("unable to sign claims: %w", err)
	}

	// Marshal final assertion
	assertion, err := msg.MarshalCBOR()
	if err != nil {
		return "", fmt.Errorf("unable to marshal assertion: %w", err)
	}

	// No error
	return base64.RawURLEncoding.EncodeToString(assertion), nil
}

func (ds *defaultSigner) ContentType() string {
	return "CWT"
}

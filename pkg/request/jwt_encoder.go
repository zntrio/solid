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

package request

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/jsonpb"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/jwk"
)

// -----------------------------------------------------------------------------

// JWSAuthorizationEncoder returns an authorization request encoder instance.
func JWSAuthorizationEncoder(alg jose.SignatureAlgorithm, KeyProvider jwk.KeyProviderFunc) AuthorizationEncoder {
	return &jwtEncoder{
		alg:         alg,
		keyProvider: KeyProvider,
	}
}

type jwtEncoder struct {
	alg         jose.SignatureAlgorithm
	keyProvider jwk.KeyProviderFunc
}

func (enc *jwtEncoder) Encode(ctx context.Context, ar *corev1.AuthorizationRequest) (string, error) {
	// Check arguments
	if ar == nil {
		return "", fmt.Errorf("unable to encode nil request")
	}

	// Retrieve the signing key
	key, err := enc.keyProvider(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve key from key provider: %w", err)
	}
	if key == nil {
		return "", fmt.Errorf("key provider returned a nil key")
	}
	if key.IsPublic() {
		return "", fmt.Errorf("key provider returned a public key")
	}

	// Encode ar as json
	jsonString, err := (&jsonpb.Marshaler{
		OrigName: true,
	}).MarshalToString(ar)
	if err != nil {
		return "", fmt.Errorf("unable to prepare request: %w", err)
	}

	// Decode using json
	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(jsonString), &claims); err != nil {
		return "", fmt.Errorf("unable to serialize request payload: %w", err)
	}

	// Preapre JWT header
	options := (&jose.SignerOptions{}).WithType("ar+jwt")

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: enc.alg, Key: key}, options)
	if err != nil {
		return "", fmt.Errorf("unable to prepare signer: %w", err)
	}

	// Generate signed token
	out, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to generate JWT encoding: %w", err)
	}

	// No error
	return out, nil
}

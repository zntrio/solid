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
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/jsonpb"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

// -----------------------------------------------------------------------------

// JWSAuthorizationDecoder returns an authorization request decoder instance.
func JWSAuthorizationDecoder() AuthorizationDecoder {
	return &jwtDecoder{}
}

type jwtDecoder struct {
}

func (d *jwtDecoder) Decode(ctx context.Context, jwksRaw []byte, value string) (*corev1.AuthorizationRequest, error) {
	// Retrieve JWK associated to the client
	if len(jwksRaw) == 0 {
		return nil, fmt.Errorf("jwks is nil")
	}

	// Validate value
	token, err := jose.ParseSigned(value)
	if err != nil {
		return nil, fmt.Errorf("unable to decode request value as a valid JWT: %w", err)
	}

	// Parse JWKS
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksRaw, &jwks); err != nil {
		return nil, fmt.Errorf("jwks is invalid: %w", err)
	}

	// Try to validate assertion with one of keys
	valid := false
	for _, k := range jwks.Keys {
		// Ignore encryption keys
		if k.Use == "enc" {
			continue
		}

		// Check assertion using key
		_, err := token.Verify(k)
		if err == nil {
			valid = true
		}

		if valid {
			break
		}
	}

	// If no valid signature found
	if !valid {
		return nil, fmt.Errorf("no valid signature found")
	}

	// Verifiy token claims
	var req corev1.AuthorizationRequest
	if err := (&jsonpb.Unmarshaler{
		AllowUnknownFields: false,
	}).Unmarshal(bytes.NewBuffer(token.UnsafePayloadWithoutVerification()), &req); err != nil {
		return nil, fmt.Errorf("unable to decode request payload: %w", err)
	}

	// No error
	return &req, nil
}

// -----------------------------------------------------------------------------

// KeyProviderFunc defines key provider contract.
type KeyProviderFunc func() (*jose.JSONWebKey, error)

// JWSAuthorizationEncoder returns an authorization request encoder instance.
func JWSAuthorizationEncoder(alg jose.SignatureAlgorithm, KeyProvider KeyProviderFunc) AuthorizationEncoder {
	return &jwtEncoder{
		alg:         alg,
		keyProvider: KeyProvider,
	}
}

type jwtEncoder struct {
	alg         jose.SignatureAlgorithm
	keyProvider KeyProviderFunc
}

func (enc *jwtEncoder) Encode(ctx context.Context, ar *corev1.AuthorizationRequest) (string, error) {
	// Check arguments
	if ar == nil {
		return "", fmt.Errorf("unable to encode nil request")
	}

	// Retrieve the signing key
	key, err := enc.keyProvider()
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

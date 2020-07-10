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

package jwsreq

import (
	"context"
	"fmt"

	"github.com/square/go-jose/v3"
	"google.golang.org/protobuf/encoding/protojson"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/jwk"
)

// -----------------------------------------------------------------------------

// JWTAuthorizationDecoder returns an authorization request decoder instance.
func JWTAuthorizationDecoder(keySetProvider jwk.KeySetProviderFunc) AuthorizationDecoder {
	return &jwtDecoder{
		keySetProvider: keySetProvider,
	}
}

type jwtDecoder struct {
	keySetProvider jwk.KeySetProviderFunc
}

func (d *jwtDecoder) Decode(ctx context.Context, value string) (*corev1.AuthorizationRequest, error) {
	// Validate value
	token, err := jose.ParseSigned(value)
	if err != nil {
		return nil, fmt.Errorf("unable to decode request value as a valid JWT: %w", err)
	}

	// Retrieve key set
	jwks, err := d.keySetProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve key set from provider: %w", err)
	}
	if jwks == nil {
		return nil, fmt.Errorf("key set provider returned a nil key set")
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("key set provider returned an empty key set")
	}

	// Try to validate assertion with one of keys
	if err := jwk.ValidateSignature(jwks, token); err != nil {
		return nil, fmt.Errorf("unable to validate request object signature: %w", err)
	}

	// Verifiy token claims
	var req corev1.AuthorizationRequest
	if err := protojson.Unmarshal(token.UnsafePayloadWithoutVerification(), &req); err != nil {
		return nil, fmt.Errorf("unable to decode request payload: %w", err)
	}

	// No error
	return &req, nil
}

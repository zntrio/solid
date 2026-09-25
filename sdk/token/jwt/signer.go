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
	"encoding/json"
	"errors"
	"fmt"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/types"
)

// ClaimsAdapter adapts arbitrary claim objects (structs, maps, protobuf
// types) to the gojwt.Claims interface. The registered-claims getters
// return zero values: claim semantics are validated by solid's services,
// never by the JWT library. MarshalJSON preserves the wrapped object's
// exact JSON form.
type ClaimsAdapter struct{ Claims any }

// MarshalJSON marshals the wrapped claim object with its exact JSON form.
func (c ClaimsAdapter) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Claims)
}

// GetExpirationTime implements the gojwt.Claims interface.
func (c ClaimsAdapter) GetExpirationTime() (*gojwt.NumericDate, error) { return nil, nil }

// GetNotBefore implements the gojwt.Claims interface.
func (c ClaimsAdapter) GetNotBefore() (*gojwt.NumericDate, error) { return nil, nil }

// GetIssuedAt implements the gojwt.Claims interface.
func (c ClaimsAdapter) GetIssuedAt() (*gojwt.NumericDate, error) { return nil, nil }

// GetAudience implements the gojwt.Claims interface.
func (c ClaimsAdapter) GetAudience() (gojwt.ClaimStrings, error) { return nil, nil }

// GetIssuer implements the gojwt.Claims interface.
func (c ClaimsAdapter) GetIssuer() (string, error) { return "", nil }

// GetSubject implements the gojwt.Claims interface.
func (c ClaimsAdapter) GetSubject() (string, error) { return "", nil }

type defaultSigner struct {
	tokenType   string
	alg         string
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
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return "", fmt.Errorf("key provider returned a unidentifiable key")
	}

	// Materialize the signing key to a native Go key.
	rawKey, err := MaterializeSigningKey(key)
	if err != nil {
		return "", err
	}

	// Resolve the signing method.
	method := gojwt.GetSigningMethod(ds.alg)
	if method == nil {
		return "", fmt.Errorf("unsupported signing algorithm %q", ds.alg)
	}

	// Build token
	tok := gojwt.NewWithClaims(method, ClaimsAdapter{Claims: claims})
	tok.Header["typ"] = ds.tokenType
	tok.Header["kid"] = kid

	// Embed the public JWK in the header (DPoP).
	if ds.embedJWK {
		pub, pubErr := jwxjwk.PublicKeyOf(key)
		if pubErr != nil {
			return "", fmt.Errorf("unable to derive public key: %w", pubErr)
		}
		tok.Header["jwk"] = pub
	}

	// Generate the final proof
	raw, err := tok.SignedString(rawKey)
	if err != nil {
		return "", fmt.Errorf("unable to generate JWT: %w", err)
	}

	// No error
	return raw, nil
}

func (ds *defaultSigner) ContentType() string {
	return "JWT"
}

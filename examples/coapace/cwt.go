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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"fmt"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
)

// cwtSigningKey returns the ephemeral ES256 (P-256) JWK used to sign CWT
// tokens in the "cwt" token-format mode, with a derived kid (RFC 7638
// thumbprint) so JWKS-style key lookups by kid resolve.
func cwtSigningKey() (jwk.Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate ephemeral CWT signing key: %w", err)
	}

	key, err := jwxjwk.Import(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to import ephemeral CWT signing key: %w", err)
	}
	if err := key.Set(jwxjwk.AlgorithmKey, cose.AlgorithmES256.String()); err != nil {
		return nil, fmt.Errorf("unable to set CWT signing key algorithm: %w", err)
	}
	if err := key.Set(jwxjwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("unable to set CWT signing key usage: %w", err)
	}
	if err := jwk.AssignKeyID(key); err != nil {
		return nil, fmt.Errorf("unable to assign CWT signing key id: %w", err)
	}
	return key, nil
}

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
	"fmt"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
)

// ML-DSA post-quantum signing support (FIPS 204, draft-ietf-cose-dilithium)
// is implemented in sdk/jwk: the AKP key type, its JWK parser, and the
// golang-jwt signing-method registrations (ML-DSA-44/65/87). Importing
// sdk/jwk registers the methods with the golang-jwt registry.

// MaterializeSigningKey resolves the raw Go key suitable for golang-jwt
// signing/verification from a jwk.Key. ML-DSA keys (AKP) are unwrapped to
// their raw crypto/mldsa key; every other key type is materialized via
// jwk.Export. The returned value is the key to pass to
// gojwt.Token.SignedString or SigningMethod.Verify.
func MaterializeSigningKey(key jwk.Key) (any, error) {
	// ML-DSA keys are not supported by jwx; unwrap them.
	if mk, ok := key.(*jwk.MLDSAKey); ok {
		if mk.PrivateKey() != nil {
			return mk.PrivateKey(), nil
		}
		if mk.MLDSPublicKey() != nil {
			return mk.MLDSPublicKey(), nil
		}
		return nil, fmt.Errorf("ML-DSA key has no key material")
	}

	var raw any
	if err := jwxjwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("unable to materialize key: %w", err)
	}
	return raw, nil
}

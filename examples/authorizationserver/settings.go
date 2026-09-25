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
	"context"
	"crypto/mldsa"
	"fmt"
	"log"
	"os"

	"zntr.io/solid/sdk/jwk"
)

// signingKeyEnvVar is the environment variable holding the example server's
// signing key as a JWK JSON document.
const signingKeyEnvVar = "SOLID_EXAMPLE_SIGNING_KEY"

// defaultSigningAlgorithm is the example server's default signing
// algorithm: post-quantum ML-DSA-65 (FIPS 204).
const defaultSigningAlgorithm = jwk.MLDSA65

// loadSigningKey returns the example server's signing key. It is loaded from
// the SOLID_EXAMPLE_SIGNING_KEY environment variable when set; otherwise an
// ephemeral ML-DSA-65 key is generated at boot with a loud warning, since an
// ephemeral key invalidates previously issued tokens on every restart.
func loadSigningKey() (jwk.Key, error) {
	if raw, ok := os.LookupEnv(signingKeyEnvVar); ok && raw != "" {
		keySet, err := jwk.Parse([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("unable to decode %s: %w", signingKeyEnvVar, err)
		}
		key, ok := keySet.Key(0)
		if !ok {
			return nil, fmt.Errorf("%s does not contain a key", signingKeyEnvVar)
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%s does not contain a valid JWK", signingKeyEnvVar)
		}
		return key, nil
	}

	log.Printf("WARNING: %s is not set; using an ephemeral ML-DSA-65 signing key. Tokens will not survive a restart; set the variable with a stable JWK for anything beyond local testing.", signingKeyEnvVar)

	// Generate a fresh ephemeral ML-DSA-65 key.
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("unable to generate ephemeral signing key: %w", err)
	}
	signingKey, err := jwk.NewMLDSAKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to import ephemeral signing key: %w", err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, defaultSigningAlgorithm); err != nil {
		return nil, fmt.Errorf("unable to set signing key algorithm: %w", err)
	}
	if err := signingKey.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("unable to set signing key usage: %w", err)
	}
	// Derive a stable kid (RFC 7638 thumbprint) so JWKS lookups and token
	// headers match.
	if err := jwk.AssignKeyID(signingKey); err != nil {
		return nil, fmt.Errorf("unable to assign signing key id: %w", err)
	}
	return signingKey, nil
}

// keyProvider returns the AS signing key provider.
func keyProvider() jwk.KeyProviderFunc {
	privateKey, err := loadSigningKey()
	if err != nil {
		panic(err)
	}

	return func(_ context.Context) (jwk.Key, error) {
		// No error
		return privateKey, nil
	}
}

// keySetProvider returns the AS public key set provider (JWKS endpoint).
func keySetProvider() jwk.KeySetProviderFunc {
	privateKey, err := loadSigningKey()
	if err != nil {
		panic(err)
	}

	pub, err := privateKey.PublicKey()
	if err != nil {
		panic(err)
	}

	return func(_ context.Context) (jwk.Set, error) {
		// No error
		set := jwk.NewSet()
		if err := set.AddKey(pub); err != nil {
			return nil, err
		}
		return set, nil
	}
}

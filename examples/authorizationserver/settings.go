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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token/hpke"
)

// signingKeyEnvVar is the environment variable holding the example server's
// signing key as a JWK JSON document.
const signingKeyEnvVar = "SOLID_EXAMPLE_SIGNING_KEY"

// defaultSigningAlgorithm is the example server's default signing
// algorithm: post-quantum ML-DSA-65 (FIPS 204).
const defaultSigningAlgorithm = jwk.MLDSA65

// loadKey returns a key provider reading its key from the given environment
// variable (a JWK JSON document); when the variable is unset or empty, gen
// generates an ephemeral key at boot with a loud warning, since an ephemeral
// key invalidates previously issued tokens on every restart. The generation
// closure prepares the key (algorithm/usage/kid) before returning it.
func loadKey(envVar string, gen func() (jwk.Key, error)) jwk.KeyProviderFunc {
	var key jwk.Key

	if raw, ok := os.LookupEnv(envVar); ok && raw != "" {
		keySet, err := jwk.Parse([]byte(raw))
		if err != nil {
			panic(fmt.Errorf("unable to decode %s: %w", envVar, err))
		}
		k, ok := keySet.Key(0)
		if !ok {
			panic(fmt.Errorf("%s does not contain a key", envVar))
		}
		if err := k.Validate(); err != nil {
			panic(fmt.Errorf("%s does not contain a valid JWK", envVar))
		}
		key = k
	} else {
		log.Printf("WARNING: %s is not set; using an ephemeral key. Tokens will not survive a restart; set the variable with a stable JWK for anything beyond local testing.", envVar)

		k, err := gen()
		if err != nil {
			panic(fmt.Errorf("unable to generate ephemeral key for %s: %w", envVar, err))
		}
		key = k
	}

	return func(_ context.Context) (jwk.Key, error) {
		// No error
		return key, nil
	}
}

// keyProvider returns the AS signing key provider: the key is loaded from
// SOLID_EXAMPLE_SIGNING_KEY when set, otherwise an ephemeral ML-DSA-65 key
// is generated at boot (see loadKey).
func keyProvider() jwk.KeyProviderFunc {
	return loadKey(signingKeyEnvVar, func() (jwk.Key, error) {
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
		// Derive a stable kid (RFC 7638 thumbprint) so JWKS lookups and
		// token headers match.
		if err := jwk.AssignKeyID(signingKey); err != nil {
			return nil, fmt.Errorf("unable to assign signing key id: %w", err)
		}
		return signingKey, nil
	})
}

// keySetProvider returns the AS public key set provider (JWKS endpoint).
// It derives the public key from the same provider as the signer so both
// sides see the identical key material and kid.
func keySetProvider() jwk.KeySetProviderFunc {
	privateKey, err := keyProvider()(context.Background())
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

// encryptionKeyEnvVar is the environment variable holding the example
// server's token encryption key as a JWK JSON document.
const encryptionKeyEnvVar = "SOLID_EXAMPLE_ENCRYPTION_KEY"

// defaultEncryptionAlgorithm is the example server's token encryption
// algorithm (draft-ietf-jose-hpke-encrypt-22): HPKE-7, Integrated
// Encryption with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
const defaultEncryptionAlgorithm = hpke.HPKE7

// encryptionKeyProvider returns the AS token encryption key provider: the
// key is loaded from SOLID_EXAMPLE_ENCRYPTION_KEY when set, otherwise an
// ephemeral P-256 key is generated at boot (see loadKey).
func encryptionKeyProvider() jwk.KeyProviderFunc {
	return loadKey(encryptionKeyEnvVar, func() (jwk.Key, error) {
		// Generate a fresh ephemeral P-256 key.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("unable to generate ephemeral encryption key: %w", err)
		}
		encryptionKey, err := jwxjwk.Import(priv)
		if err != nil {
			return nil, fmt.Errorf("unable to import ephemeral encryption key: %w", err)
		}
		// Note: the JWK alg member is deliberately not set — "HPKE-7" is a
		// draft-ietf-jose-hpke-encrypt suite identifier, not a registered
		// JOSE key algorithm, and jwx rejects it on Set. The suite is
		// selected by the hpke.Encrypter constructor argument.
		if err := encryptionKey.Set(jwk.KeyUsageKey, "enc"); err != nil {
			return nil, fmt.Errorf("unable to set encryption key usage: %w", err)
		}
		// Derive a stable kid (RFC 7638 thumbprint) so token headers and
		// key lookups match.
		if err := jwk.AssignKeyID(encryptionKey); err != nil {
			return nil, fmt.Errorf("unable to assign encryption key id: %w", err)
		}
		return encryptionKey, nil
	})
}

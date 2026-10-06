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

package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
)

type claimsOfSubject struct {
	Sub string `json:"sub"`
}

func TestClaimsOf(t *testing.T) {
	ctx := context.Background()

	// Signing key pair with a stable kid.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := jwxjwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := privKey.Set(jwxjwk.KeyIDKey, "claims-of-key"); err != nil {
		t.Fatal(err)
	}
	keyProvider := func(context.Context) (jwk.Key, error) { return privKey, nil }

	pubKey, err := jwxjwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwxjwk.KeyIDKey, "claims-of-key"); err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	pubSet := jwk.NewSet()
	if err := pubSet.AddKey(pubKey); err != nil {
		t.Fatal(err)
	}

	signer := jwt.AccessTokenSigner("ES256", keyProvider)
	verifier := jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return pubSet, nil }, jwt.SupportedSignAlgorithms())

	t.Run("decodes typed claims", func(t *testing.T) {
		raw, err := signer.Sign(ctx, map[string]any{"sub": "user-42"})
		if err != nil {
			t.Fatal(err)
		}
		claims, err := token.ClaimsOf[claimsOfSubject](ctx, verifier, raw)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Sub != "user-42" {
			t.Fatalf("sub = %q, want user-42", claims.Sub)
		}
	})

	t.Run("rejects a bad signature", func(t *testing.T) {
		raw, err := signer.Sign(ctx, map[string]any{"sub": "user-42"})
		if err != nil {
			t.Fatal(err)
		}
		// Flip the signature bytes: verification must fail before
		// any decode work.
		tampered := raw[:len(raw)-4] + "AAAA"
		if _, err := token.ClaimsOf[claimsOfSubject](ctx, verifier, tampered); err == nil {
			t.Fatal("bad signature: expected error, got none")
		}
	})
}

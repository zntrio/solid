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
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
)

// cwtClaims mirrors the RFC 8392 section 3.1 claims set: integer keys
// 1 (iss), 2 (sub), 4 (exp).
type cwtClaims struct {
	Iss string `cbor:"1,keyasint,omitempty"`
	Sub string `cbor:"2,keyasint,omitempty"`
	Exp uint64 `cbor:"4,keyasint,omitempty"`
}

// privateKeyFixture returns a jwk.Key carrying a P-256 private key with
// kid set, plus the KeyProviderFunc exposing it.
func privateKeyFixture(t *testing.T, kid string) (jwk.Key, jwk.KeyProviderFunc) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	k, err := jwxjwk.Import(key)
	if err != nil {
		t.Fatalf("unable to import private key: %v", err)
	}
	if err := k.Set(jwxjwk.KeyIDKey, kid); err != nil {
		t.Fatalf("unable to set key id: %v", err)
	}
	return k, func(context.Context) (jwk.Key, error) {
		return k, nil
	}
}

func Test_defaultSigner_Serialize(t *testing.T) {
	_, keyProvider := privateKeyFixture(t, "signing-key-1")

	claims := cwtClaims{
		Iss: "https://as.example.com",
		Sub: "pairwise-subject-1",
		Exp: 2000000000,
	}

	raw, err := AccessTokenSigner(cose.AlgorithmES256, keyProvider).Serialize(context.Background(), claims)
	if err != nil {
		t.Fatalf("unable to serialize claims: %v", err)
	}
	if raw == "" {
		t.Fatal("expected a serialized token")
	}

	// The result must decode as a COSE_Sign1_Tagged object with the
	// expected protected header parameters.
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("serialized token is not base64url: %v", err)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		t.Fatalf("serialized token is not a COSE_Sign1: %v", err)
	}

	if alg, err := msg.Headers.Protected.Algorithm(); err != nil || alg != cose.AlgorithmES256 {
		t.Errorf("protected alg = %v, %v; want ES256", alg, err)
	}
	if kid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]; !ok || string(kid.([]byte)) != "signing-key-1" {
		t.Errorf("protected kid = %v; want []byte(signing-key-1)", kid)
	}
	if typ, ok := msg.Headers.Protected[cose.HeaderLabelType]; !ok || typ != "application/at+cwt" {
		t.Errorf("protected typ = %v; want application/at+cwt", typ)
	}

	// The payload must decode back to the input claims (integer keys).
	var decoded cwtClaims
	if err := cbor.Unmarshal(msg.Payload, &decoded); err != nil {
		t.Fatalf("unable to decode payload claims: %v", err)
	}
	if decoded != claims {
		t.Errorf("decoded claims = %+v; want %+v", decoded, claims)
	}
}

func Test_defaultSigner_Serialize_errors(t *testing.T) {
	key, keyProvider := privateKeyFixture(t, "signing-key-1")
	ctx := context.Background()

	// Public key provider: unusable for signing.
	pub, err := jwxjwk.PublicKeyOf(key)
	if err != nil {
		t.Fatalf("unable to derive public key: %v", err)
	}
	pubProvider := func(context.Context) (jwk.Key, error) {
		return pub, nil
	}

	tests := []struct {
		name         string
		alg          cose.Algorithm
		claims       any
		keyProvider  jwk.KeyProviderFunc
		wantEmptyErr bool
	}{
		{
			name:         "nil claims",
			alg:          cose.AlgorithmES256,
			keyProvider:  keyProvider,
			wantEmptyErr: true,
		},
		{
			name:         "nil key provider",
			alg:          cose.AlgorithmES256,
			claims:       cwtClaims{},
			wantEmptyErr: true,
		},
		{
			name:         "public key",
			alg:          cose.AlgorithmES256,
			claims:       cwtClaims{},
			keyProvider:  pubProvider,
			wantEmptyErr: true,
		},
		{
			name:         "unsupported algorithm",
			alg:          cose.AlgorithmPS256,
			claims:       cwtClaims{},
			keyProvider:  keyProvider,
			wantEmptyErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var provider jwk.KeyProviderFunc
			if tt.keyProvider != nil {
				provider = tt.keyProvider
			} else if tt.name == "nil key provider" {
				provider = nil
			} else {
				provider = keyProvider
			}
			var claims any = tt.claims
			if tt.name == "nil claims" {
				claims = nil
			}
			raw, err := AccessTokenSigner(tt.alg, provider).Serialize(ctx, claims)
			if err == nil || raw != "" {
				t.Errorf("Serialize() = %q, %v; want error", raw, err)
			}
		})
	}
}

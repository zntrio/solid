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

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

func staticKeySet(set jwk.Set) jwk.KeySetProviderFunc {
	return func(context.Context) (jwk.Set, error) {
		return set, nil
	}
}

// keySetFromECDSA converts an ECDSA public key into a jwk.Set.
func keySetFromECDSA(t *testing.T, key *ecdsa.PrivateKey, kid string) jwk.Set {
	t.Helper()

	set := jwk.NewSet()
	pub, err := jwxjwk.Import(&key.PublicKey)
	if err != nil {
		t.Fatalf("unable to import public key: %v", err)
	}
	if err := pub.Set(jwxjwk.KeyIDKey, kid); err != nil {
		t.Fatalf("unable to set key id: %v", err)
	}
	if err := pub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatalf("unable to set key algorithm: %v", err)
	}
	if err := set.Set("keys", []jwk.Key{pub}); err != nil {
		t.Fatalf("unable to build key set: %v", err)
	}
	return set
}

// signCWT signs the fixture claims with the given ECDSA private key and
// returns the base64url COSE_Sign1 token.
func signCWT(t *testing.T, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()

	k, err := jwxjwk.Import(key)
	if err != nil {
		t.Fatalf("unable to import private key: %v", err)
	}
	if err := k.Set(jwxjwk.KeyIDKey, kid); err != nil {
		t.Fatalf("unable to set key id: %v", err)
	}
	raw, err := AccessTokenSigner(cose.AlgorithmES256, func(context.Context) (jwk.Key, error) {
		return k, nil
	}).Sign(context.Background(), cwtClaims{
		Iss: "https://as.example.com",
		Sub: "pairwise-subject-1",
		Exp: 2000000000,
	})
	if err != nil {
		t.Fatalf("unable to sign claims: %v", err)
	}
	return raw
}

// tamperSignature flips the last byte of the decoded COSE_Sign1 signature
// and re-encodes, invalidating the signature.
func tamperSignature(t *testing.T, raw string) string {
	t.Helper()

	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("unable to decode token: %v", err)
	}
	data[len(data)-1] ^= 0xff
	return base64.RawURLEncoding.EncodeToString(data)
}

func Test_defaultVerifier_Verify(t *testing.T) {
	// The trusted key pair: the key set exposes the public key, the
	// token fixtures are signed with the private one.
	trustedKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	trustedSet := keySetFromECDSA(t, trustedKey, "trusted-key-1")
	trustedToken := signCWT(t, trustedKey, "trusted-key-1")

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate foreign signing key: %v", err)
	}
	foreignSet := keySetFromECDSA(t, foreignKey, "foreign-key-1")
	foreignToken := signCWT(t, foreignKey, "foreign-key-1")

	// A token whose kid is absent from the set falls back to every
	// candidate key.
	unknownKidSet := keySetFromECDSA(t, trustedKey, "another-key-id")
	unknownKidToken := signCWT(t, trustedKey, "unknown-kid")

	// Tag-98 (COSE_Sign) prefixed garbage: valid CBOR array, wrong tag.
	wrongTagBytes := base64.RawURLEncoding.EncodeToString([]byte{0xd3, 0x84, 0x40, 0x40, 0x40, 0x40})

	tests := []struct {
		name                string
		keySetProvider      jwk.KeySetProviderFunc
		supportedAlgorithms []cose.Algorithm
		token               string
		wantErr             bool
	}{
		{
			name:                "blank",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			wantErr:             true,
		},
		{
			name:                "not base64url",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               "@@@@",
			wantErr:             true,
		},
		{
			name:                "random bytes",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               base64.RawURLEncoding.EncodeToString([]byte("definitely not cbor")),
			wantErr:             true,
		},
		{
			name:                "wrong cose tag",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               wrongTagBytes,
			wantErr:             true,
		},
		{
			name:                "valid",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               trustedToken,
		},
		{
			name:                "foreign key set",
			keySetProvider:      staticKeySet(foreignSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               trustedToken,
			wantErr:             true,
		},
		{
			name:                "tampered signature",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               tamperSignature(t, trustedToken),
			wantErr:             true,
		},
		{
			name:                "unsupported algorithm allowlist",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES384},
			token:               trustedToken,
			wantErr:             true,
		},
		{
			name:                "kid routing matches",
			keySetProvider:      staticKeySet(trustedSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               trustedToken,
		},
		{
			name:                "unknown kid falls back to candidates",
			keySetProvider:      staticKeySet(unknownKidSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               unknownKidToken,
		},
		{
			name:                "foreign token with unknown kid",
			keySetProvider:      staticKeySet(unknownKidSet),
			supportedAlgorithms: []cose.Algorithm{cose.AlgorithmES256},
			token:               foreignToken,
			wantErr:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := DefaultVerifier(tt.keySetProvider, tt.supportedAlgorithms)
			err := v.Verify(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_defaultVerifier_Claims(t *testing.T) {
	trustedKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	trustedSet := keySetFromECDSA(t, trustedKey, "trusted-key-1")
	trustedToken := signCWT(t, trustedKey, "trusted-key-1")

	v := DefaultVerifier(staticKeySet(trustedSet), []cose.Algorithm{cose.AlgorithmES256})

	var claims cwtClaims
	if err := v.Claims(context.Background(), trustedToken, &claims); err != nil {
		t.Fatalf("unable to verify claims: %v", err)
	}
	if claims.Iss != "https://as.example.com" || claims.Sub != "pairwise-subject-1" || claims.Exp != 2000000000 {
		t.Errorf("decoded claims = %+v; want the signed fixture claims", claims)
	}

	// Foreign key set must fail with the canonical signature error.
	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate foreign key: %v", err)
	}
	vForeign := DefaultVerifier(staticKeySet(keySetFromECDSA(t, foreignKey, "foreign-key-1")), []cose.Algorithm{cose.AlgorithmES256})
	if err := vForeign.Claims(context.Background(), trustedToken, &claims); err != token.ErrInvalidTokenSignature {
		t.Errorf("Claims() with foreign key set error = %v; want token.ErrInvalidTokenSignature", err)
	}
}

func Test_defaultVerifier_Parse(t *testing.T) {
	trustedKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	trustedToken := signCWT(t, trustedKey, "trusted-key-1")

	v := DefaultVerifier(nil, nil)

	tk, err := v.Parse(trustedToken)
	if err != nil {
		t.Fatalf("unable to parse token: %v", err)
	}

	if alg, err := tk.Algorithm(); err != nil || alg != "ES256" {
		t.Errorf("Algorithm() = %q, %v; want ES256", alg, err)
	}
	if kid, err := tk.KeyID(); err != nil || kid != "trusted-key-1" {
		t.Errorf("KeyID() = %q, %v; want trusted-key-1", kid, err)
	}
	if typ, err := tk.Type(); err != nil || typ != "application/at+cwt" {
		t.Errorf("Type() = %q, %v; want application/at+cwt", typ, err)
	}
	if _, err := tk.PublicKey(); err == nil {
		t.Error("PublicKey() should error on cwt tokens")
	}
	if _, err := tk.PublicKeyThumbPrint(); err == nil {
		t.Error("PublicKeyThumbPrint() should error on cwt tokens")
	}

	var claims cwtClaims
	if err := tk.UnverifiedClaims(&claims); err != nil {
		t.Fatalf("unable to decode unverified claims: %v", err)
	}
	if claims.Sub != "pairwise-subject-1" {
		t.Errorf("unverified sub = %q; want pairwise-subject-1", claims.Sub)
	}

	// Garbage input.
	if _, err := v.Parse("garbage"); err == nil {
		t.Error("Parse() should error on garbage input")
	}
}

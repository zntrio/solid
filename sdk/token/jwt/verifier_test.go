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
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

func Test_defaultVerifier_Parse(t *testing.T) {
	type fields struct {
		keySetProvider      jwk.KeySetProviderFunc
		supportedAlgorithms []string
	}
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    token.Token
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank",
			args: args{
				token: "",
			},
			wantErr: true,
		},
		{
			name: "invalid",
			args: args{
				token: "...",
			},
			wantErr: true,
		},
		{
			name: "valid",
			fields: fields{
				supportedAlgorithms: []string{"ES384"},
			},
			args: args{
				token: "eyJhbGciOiJFUzM4NCIsImtpZCI6ImZvbyIsInR5cCI6IiJ9.eyJ0ZXN0IjoiZXhhbXBsZSJ9.a-vdiRCDSIlZdm-gRIk4dxfvsHT90W6a-Lt9JiGF4CMJCrLgl0zZAI57rjTRZXGd3PB0tAoZ8dM0OUQTOIxORkdvQlPYpvM_fEppcYfRkwUO8n7iswsvS4GqSJgotacf",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &defaultVerifier{
				keySetProvider:      tt.fields.keySetProvider,
				supportedAlgorithms: tt.fields.supportedAlgorithms,
			}
			_, err := v.Parse(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_defaultVerifier_Verify(t *testing.T) {
	// The trusted key pair: the key set exposes the public key, the
	// token fixtures are signed with the private one.
	trustedKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	trustedSet := keySetFromECDSA(t, trustedKey)
	trustedToken := es256Token(t, trustedKey)

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate foreign signing key: %v", err)
	}
	foreignToken := es256Token(t, foreignKey)

	tests := []struct {
		name                string
		supportedAlgorithms []string
		token               string
		wantErr             bool
	}{
		{
			name:    "blank",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid syntax",
			token:   "...",
			wantErr: true,
		},
		{
			name:                "alg not supported",
			supportedAlgorithms: []string{"ES256"},
			token:               "eyJhbGciOiJFUzM4NCIsImtpZCI6ImZvbyIsInR5cCI6IiJ9.eyJ0ZXN0IjoiZXhhbXBsZSJ9.a-vdiRCDSIlZdm-gRIk4dxfvsHT90W6a-Lt9JiGF4CMJCrLgl0zZAI57rjTRZXGd3PB0tAoZ8dM0OUQTOIxORkdvQlPYpvM_fEppcYfRkwUO8n7iswsvS4GqSJgotacf",
			wantErr:             true,
		},
		{
			// Verify is a signature check: a token signed by the
			// trusted key MUST verify.
			name:                "trusted signature verifies",
			supportedAlgorithms: []string{"ES256"},
			token:               trustedToken,
			wantErr:             false,
		},
		{
			// A well-formed token signed by an untrusted key MUST
			// fail: Verify never accepts on syntax alone.
			name:                "untrusted signature rejected",
			supportedAlgorithms: []string{"ES256"},
			token:               foreignToken,
			wantErr:             true,
		},
		{
			// Tampering with the payload invalidates the signature.
			name:                "tampered payload rejected",
			supportedAlgorithms: []string{"ES256"},
			token:               tamperPayload(t, trustedToken),
			wantErr:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &defaultVerifier{
				keySetProvider:      staticKeySet(trustedSet),
				supportedAlgorithms: tt.supportedAlgorithms,
			}
			if err := v.Verify(tt.token); (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// staticKeySet wraps a jwk.Set into a provider function.
func staticKeySet(set jwk.Set) jwk.KeySetProviderFunc {
	return func(context.Context) (jwk.Set, error) {
		return set, nil
	}
}

// keySetFromECDSA converts an ECDSA public key into a jwk.Set.
func keySetFromECDSA(t *testing.T, key *ecdsa.PrivateKey) jwk.Set {
	t.Helper()

	set := jwk.NewSet()
	pub, err := jwxjwk.Import(&key.PublicKey)
	if err != nil {
		t.Fatalf("unable to import public key: %v", err)
	}
	if err := pub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatalf("unable to set key algorithm: %v", err)
	}
	if err := set.Set("keys", []jwk.Key{pub}); err != nil {
		t.Fatalf("unable to build key set: %v", err)
	}
	return set
}

// es256Token signs example claims with the given ECDSA private key.
func es256Token(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	signed, err := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"test": "example",
	}).SignedString(key)
	if err != nil {
		t.Fatalf("unable to sign token: %v", err)
	}
	return signed
}

// tamperPayload replaces the payload segment of a compact JWT with a
// different valid base64url value, invalidating the signature.
func tamperPayload(t *testing.T, raw string) string {
	t.Helper()

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %q", raw)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"test":"tampered"}`))
	return strings.Join(parts, ".")
}

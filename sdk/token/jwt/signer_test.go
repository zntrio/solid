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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
)

var jwkPrivateKey = []byte(`{
	"kid": "foo",
    "kty": "EC",
    "d": "Uwq56PhVB6STB8MvLQWcOsKQlZbBvWFQba8D6Uhb2qDunpzqvoNyFsnAHKS_AkQB",
    "use": "sig",
    "crv": "P-384",
    "x": "m2NDaWfRRGlCkUa4FK949uLtMqitX1lYgi8UCIMtsuR60ux3d00XBlsC6j_YDOTe",
    "y": "6vxuUq3V1aoWi4FQ_h9ZNwUsmcGP8Uuqq_YN5dhP0U8lchdmZJbLF9mPiimo_6p4",
    "alg": "ES384"
}`)

// parsePrivateKeyFixture decodes the EC private key JWK fixture.
func parsePrivateKeyFixture(t *testing.T) jwk.Key {
	t.Helper()

	k, err := jwxjwk.ParseKey(jwkPrivateKey)
	if err != nil {
		t.Fatalf("unable to parse key fixture: %v", err)
	}
	return k
}

func Test_defaultSigner_Sign(t *testing.T) {
	type fields struct {
		tokenType   string
		alg         string
		keyProvider jwk.KeyProviderFunc
	}
	type args struct {
		ctx    context.Context
		claims any
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil claims",
			args: args{
				claims: nil,
			},
			wantErr: true,
		},
		{
			name: "nil keyprovider",
			fields: fields{
				keyProvider: nil,
			},
			args: args{
				claims: map[string]string{
					"test": "test",
				},
			},
			wantErr: true,
		},
		{
			name: "keyprovider error",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					return nil, errors.New("test")
				},
			},
			args: args{
				claims: map[string]string{
					"test": "test",
				},
			},
			wantErr: true,
		},
		{
			name: "keyprovider returns nil key",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					return nil, nil
				},
			},
			args: args{
				claims: map[string]string{
					"test": "test",
				},
			},
			wantErr: true,
		},
		{
			name: "keyprovider returns unnamed key",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					k, err := jwxjwk.ParseKey(jwkPrivateKey)
					if err != nil {
						return nil, err
					}
					if err := k.Remove(jwxjwk.KeyIDKey); err != nil {
						return nil, err
					}
					return k, nil
				},
			},
			args: args{
				claims: map[string]string{
					"test": "test",
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					return parsePrivateKeyFixture(t), nil
				},
				alg: "no-such-algorithm",
			},
			args: args{
				claims: map[string]string{
					"test": "test",
				},
			},
			wantErr: true,
		},
		{
			name: "algorithm key mismatch",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					return parsePrivateKeyFixture(t), nil
				},
				alg: "ES256",
			},
			args: args{
				claims: map[string]string{
					"test": "test",
				},
			},
			wantErr: true,
		},
		{
			name: "not serializable claims",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					return parsePrivateKeyFixture(t), nil
				},
				alg: "ES384",
			},
			args: args{
				claims: map[string]any{
					"test": make(chan struct{}),
				},
			},
			wantErr: true,
		},
		{
			name: "valid",
			fields: fields{
				keyProvider: func(ctx context.Context) (jwk.Key, error) {
					return parsePrivateKeyFixture(t), nil
				},
				alg: "ES384",
			},
			args: args{
				claims: map[string]any{
					"test": "example",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &defaultSigner{
				tokenType:   tt.fields.tokenType,
				alg:         tt.fields.alg,
				keyProvider: tt.fields.keyProvider,
			}
			raw, err := ds.Serialize(tt.args.ctx, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.name == "valid" {
				// Wire-format regression check: typ/kid headers.
				parts := strings.Split(raw, ".")
				if len(parts) != 3 {
					t.Fatalf("expected compact JWT, got %d parts", len(parts))
				}
				hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
				if err != nil {
					t.Fatal(err)
				}
				var hdr map[string]any
				if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
					t.Fatal(err)
				}
				if hdr["typ"] != tt.fields.tokenType && tt.fields.tokenType != "" {
					t.Errorf("typ header = %v", hdr["typ"])
				}
				if hdr["kid"] != "foo" {
					t.Errorf("kid header = %v, want foo", hdr["kid"])
				}
				if hdr["alg"] != "ES384" {
					t.Errorf("alg header = %v", hdr["alg"])
				}

				// Claims round-trip byte-exact through decodeClaims.
				var out map[string]any
				if err := decodeClaims(parts, &out); err != nil {
					t.Fatal(err)
				}
				if out["test"] != "example" {
					t.Errorf("claims round-trip lost value: %v", out)
				}
			}
		})
	}
}

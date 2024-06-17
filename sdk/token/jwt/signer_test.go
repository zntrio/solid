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
	"testing"

	"github.com/go-jose/go-jose/v4"

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

func Test_defaultSigner_Sign(t *testing.T) {
	type fields struct {
		tokenType   string
		alg         jose.SignatureAlgorithm
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
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
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
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
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
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					return &jose.JSONWebKey{}, nil
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
			name: "signer error",
			fields: fields{
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwkPrivateKey, &privateKey)

					return &privateKey, err
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
			name: "signer algorithm mismatch",
			fields: fields{
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwkPrivateKey, &privateKey)

					return &privateKey, err
				},
				alg: jose.RS256,
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
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwkPrivateKey, &privateKey)

					return &privateKey, err
				},
				alg: jose.ES384,
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
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwkPrivateKey, &privateKey)

					return &privateKey, err
				},
				alg: jose.ES384,
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
			_, err := ds.Serialize(tt.args.ctx, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

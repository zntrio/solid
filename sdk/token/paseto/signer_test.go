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

package paseto

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"zntr.io/solid/sdk/jwk"
)

var jwkPrivateKey = []byte(`{
    "kty": "OKP",
    "d": "V4DHIXbNhNYlQTpt0wF63jf1X2s_NQ5hR0jYNkUGwvw",
    "use": "sig",
    "crv": "Ed25519",
    "kid": "D51N16r8gfKNr9nnwP2_9Nim36bm85y5zfmVxOiYJRE",
    "x": "doTK-UjiJwt83e55msjycnSgcprjN50YtI-MDVCctvY",
    "alg": "EdDSA"
}`)

func Test_defaultSigner_Sign(t *testing.T) {
	type fields struct {
		tokenType   string
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
			name: "keyprovider returns invalid key type",
			fields: fields{
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					return &jose.JSONWebKey{
						KeyID: "123",
						Key:   []byte{},
					}, nil
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
			name: "not serializable claims",
			fields: fields{
				keyProvider: func(ctx context.Context) (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwkPrivateKey, &privateKey)

					return &privateKey, err
				},
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

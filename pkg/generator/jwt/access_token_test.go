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
	"fmt"
	"testing"

	"github.com/square/go-jose/v3"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

var jwtPrivateKey = []byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)

func Test_accessTokenGenerator_Generate(t *testing.T) {
	type fields struct {
		alg         jose.SignatureAlgorithm
		keyProvider KeyProviderFunc
	}
	type args struct {
		ctx  context.Context
		jti  string
		meta *corev1.TokenMeta
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name:    "empty jti",
			wantErr: true,
			fields: fields{
				keyProvider: nil,
			},
		},
		{
			name: "empty jti",
			fields: fields{
				keyProvider: func() (*jose.JSONWebKey, error) {
					return nil, nil
				},
			},
			args: args{
				jti: "",
			},
			wantErr: true,
		},
		{
			name: "nil meta",
			fields: fields{
				keyProvider: func() (*jose.JSONWebKey, error) {
					return nil, nil
				},
			},
			args: args{
				jti:  "123456789",
				meta: nil,
			},
			wantErr: true,
		},
		{
			name: "key provider error",
			fields: fields{
				keyProvider: func() (*jose.JSONWebKey, error) {
					return nil, fmt.Errorf("foo")
				},
			},
			args: args{
				jti:  "123456789",
				meta: &corev1.TokenMeta{},
			},
			wantErr: true,
		},
		{
			name: "nil key",
			fields: fields{
				keyProvider: func() (*jose.JSONWebKey, error) {
					return nil, nil
				},
			},
			args: args{
				jti:  "123456789",
				meta: &corev1.TokenMeta{},
			},
			wantErr: true,
		},
		{
			name: "invalid algorithm",
			fields: fields{
				alg: "foo",
				keyProvider: func() (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwtPrivateKey, &privateKey)
					if err != nil {
						return nil, fmt.Errorf("unable to decode JWK: %w", err)
					}
					return &privateKey, nil
				},
			},
			args: args{
				jti: "123456789",
				meta: &corev1.TokenMeta{
					Issuer:    "http://localhost:8080",
					Audience:  "azertyuiop",
					ClientId:  "789456",
					ExpiresAt: 3601,
					IssuedAt:  1,
				},
			},
			wantErr: true,
		},
		{
			name: "algorithm / key mismatch",
			fields: fields{
				alg: jose.RS256,
				keyProvider: func() (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwtPrivateKey, &privateKey)
					if err != nil {
						return nil, fmt.Errorf("unable to decode JWK: %w", err)
					}
					return &privateKey, nil
				},
			},
			args: args{
				jti: "123456789",
				meta: &corev1.TokenMeta{
					Issuer:    "http://localhost:8080",
					Audience:  "azertyuiop",
					ClientId:  "789456",
					ExpiresAt: 3601,
					IssuedAt:  1,
				},
			},
			wantErr: true,
		},
		{
			name: "ec256 sign",
			fields: fields{
				alg: jose.ES256,
				keyProvider: func() (*jose.JSONWebKey, error) {
					var privateKey jose.JSONWebKey

					// Decode JWK
					err := json.Unmarshal(jwtPrivateKey, &privateKey)
					if err != nil {
						return nil, fmt.Errorf("unable to decode JWK: %w", err)
					}
					return &privateKey, nil
				},
			},
			args: args{
				jti: "123456789",
				meta: &corev1.TokenMeta{
					Issuer:    "http://localhost:8080",
					Audience:  "azertyuiop",
					ClientId:  "789456",
					ExpiresAt: 3601,
					IssuedAt:  1,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &accessTokenGenerator{
				alg:         tt.fields.alg,
				keyProvider: tt.fields.keyProvider,
			}
			_, err := c.Generate(tt.args.ctx, tt.args.jti, tt.args.meta)
			if (err != nil) != tt.wantErr {
				t.Errorf("accessTokenGenerator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

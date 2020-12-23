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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/dchest/uniuri"
	"github.com/square/go-jose/v3"
)

func Test_defaultSigner_Sign(t *testing.T) {
	type fields struct {
		privateKey jose.SigningKey
		options    *jose.SignerOptions
	}
	type args struct {
		claims interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil claims",
			wantErr: true,
		},
		{
			name: "public key",
			fields: fields{
				privateKey: func() jose.SigningKey {
					// Generate an ephemeral key for DPoP signer
					pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						t.Fatal(err)
					}

					return jose.SigningKey{
						Algorithm: jose.ES384,
						Key: &jose.JSONWebKey{
							Use:   "sig",
							Key:   pk.Public(),
							KeyID: "key-id-1",
						},
					}
				}(),
				options: &jose.SignerOptions{},
			},
			args: args{
				claims: struct {
					NonJsonifiable chan interface{}
				}{
					NonJsonifiable: make(chan interface{}),
				},
			},
			wantErr: true,
		},
		{
			name: "non json serializable",
			fields: fields{
				privateKey: func() jose.SigningKey {
					// Generate an ephemeral key for DPoP signer
					pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						t.Fatal(err)
					}

					return jose.SigningKey{
						Algorithm: jose.ES384,
						Key: &jose.JSONWebKey{
							Use:   "sig",
							Key:   pk,
							KeyID: "12345678",
						},
					}
				}(),
				options: &jose.SignerOptions{},
			},
			args: args{
				claims: struct {
					NonJsonifiable chan interface{}
				}{
					NonJsonifiable: make(chan interface{}),
				},
			},
			wantErr: true,
		},
		{
			name: "valid",
			fields: fields{
				privateKey: func() jose.SigningKey {
					// Generate an ephemeral key for DPoP signer
					pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						t.Fatal(err)
					}

					return jose.SigningKey{
						Algorithm: jose.ES384,
						Key: &jose.JSONWebKey{
							Use:   "sig",
							Key:   pk,
							KeyID: uniuri.NewLen(8),
						},
					}
				}(),
				options: &jose.SignerOptions{},
			},
			args: args{
				claims: struct {
					JTI string `json:"jti"`
				}{
					JTI: uniuri.New(),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := DefaultSigner(tt.fields.privateKey, tt.fields.options)
			_, err := ds.Sign(tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

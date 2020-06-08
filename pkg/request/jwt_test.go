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

package request

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/square/go-jose/v3"
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/jwk"
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(wrappers.StringValue{}),
		cmpopts.IgnoreUnexported(corev1.AuthorizationRequest{}),
	}
)

var jwtPrivateKey = []byte(`{"kid":"foo", "kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)
var jwtPublicKeySet = []byte(`{"keys":[{"kid":"foo", "kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`)

func mustJWK(body []byte) *jose.JSONWebKey {
	var key jose.JSONWebKey
	if err := json.Unmarshal(body, &key); err != nil {
		panic(err)
	}
	return &key
}

func mustJWKS(body []byte) *jose.JSONWebKeySet {
	var key jose.JSONWebKeySet
	if err := json.Unmarshal(body, &key); err != nil {
		panic(err)
	}
	return &key
}

func Test_jwtEncoder_Encode(t *testing.T) {
	type fields struct {
		alg         jose.SignatureAlgorithm
		keyProvider jwk.KeyProviderFunc
	}
	type args struct {
		ctx context.Context
		ar  *corev1.AuthorizationRequest
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
			name: "nil request",
			args: args{
				ctx: context.Background(),
				ar:  nil,
			},
			wantErr: true,
		},
		{
			name: "keyProvider error",
			fields: fields{
				alg: jose.ES256,
				keyProvider: func(_ context.Context) (*jose.JSONWebKey, error) {
					return nil, fmt.Errorf("foo")
				},
			},
			args: args{
				ctx: context.Background(),
				ar:  &corev1.AuthorizationRequest{},
			},
			wantErr: true,
		},
		{
			name: "keyProvider nil result",
			fields: fields{
				alg: jose.ES256,
				keyProvider: func(_ context.Context) (*jose.JSONWebKey, error) {
					return nil, nil
				},
			},
			args: args{
				ctx: context.Background(),
				ar:  &corev1.AuthorizationRequest{},
			},
			wantErr: true,
		},
		{
			name: "keyProvider public key result",
			fields: fields{
				alg: jose.ES256,
				keyProvider: func(_ context.Context) (*jose.JSONWebKey, error) {
					p := mustJWK(jwtPrivateKey).Public()
					return &p, nil
				},
			},
			args: args{
				ctx: context.Background(),
				ar:  &corev1.AuthorizationRequest{},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			fields: fields{
				alg: jose.ES256,
				keyProvider: func(_ context.Context) (*jose.JSONWebKey, error) {
					k := mustJWK(jwtPrivateKey)
					return k, nil
				},
			},
			args: args{
				ctx: context.Background(),
				ar: &corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := JWSAuthorizationEncoder(tt.fields.alg, tt.fields.keyProvider)
			_, err := enc.Encode(tt.args.ctx, tt.args.ar)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwtEncoder.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_jwtDecoder_Decode(t *testing.T) {
	type fields struct {
		keySetProvider jwk.KeySetProviderFunc
	}
	type args struct {
		ctx     context.Context
		jwksRaw []byte
		value   string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *corev1.AuthorizationRequest
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			fields: fields{
				keySetProvider: func(_ context.Context) (*jose.JSONWebKeySet, error) {
					jwks := mustJWKS(jwtPublicKeySet)
					return jwks, nil
				},
			},
			args: args{
				ctx:   context.Background(),
				value: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImZvbyIsInR5cCI6ImFyK2p3dCJ9.eyJhdWRpZW5jZSI6Im1EdUdjTGptYW1qTnBMbVlaTUxJc2hGY1hVRENORGNIIiwiY2xpZW50X2lkIjoiczZCaGRSa3F0MyIsImNvZGVfY2hhbGxlbmdlIjoiSzItbHRjODNhY2M0aDBjOXc2RVNDX3JFTVRKM2J3dy11Q0hhb2VLMXQ4VSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJub25jZSI6IlhEd2JCSDRNb2tVOEJtcloiLCJwcm9tcHQiOiJjb25zZW50IiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9jbGllbnQuZXhhbXBsZS5vcmcvY2IiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgb2ZmbGluZV9hY2Nlc3MiLCJzdGF0ZSI6Im9FU0lpdW95YlZ4QUo1ZkFLbXh4TTZzMkNuVmljNnpVIn0.LjwdcB6wCjDdC-CoN7OIfVi8pkFn7znInjwa4J4oTRAfSij-ou2xcpGyvsOYjo__qd8_PDYaMCzRcpH7O2k43w",
			},
			wantErr: false,
			want: &corev1.AuthorizationRequest{
				Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
				ResponseType:        "code",
				Scope:               "openid profile email offline_access",
				ClientId:            "s6BhdRkqt3",
				State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
				Nonce:               "XDwbBH4MokU8BmrZ",
				RedirectUri:         "https://client.example.org/cb",
				CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
				CodeChallengeMethod: "S256",
				Prompt:              &wrappers.StringValue{Value: "consent"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := JWSAuthorizationDecoder(tt.fields.keySetProvider)
			got, err := d.Decode(tt.args.ctx, tt.args.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwtDecoder.Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("jwtDecoder.Decode() res =%s", diff)
			}
		})
	}
}

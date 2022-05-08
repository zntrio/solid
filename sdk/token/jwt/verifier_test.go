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
	"testing"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
)

func Test_defaultVerifier_Parse(t *testing.T) {
	type fields struct {
		keySetProvider      jwk.KeySetProviderFunc
		supportedAlgorithms types.StringArray
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
	type fields struct {
		keySetProvider      jwk.KeySetProviderFunc
		supportedAlgorithms types.StringArray
	}
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "blank",
			args: args{
				token: "",
			},
			wantErr: true,
		},
		{
			name: "invalid syntax",
			args: args{
				token: "...",
			},
			wantErr: true,
		},
		{
			name: "alg not supported",
			fields: fields{
				supportedAlgorithms: types.StringArray([]string{"ES256"}),
			},
			args: args{
				token: "eyJhbGciOiJFUzM4NCIsImtpZCI6ImZvbyIsInR5cCI6IiJ9.eyJ0ZXN0IjoiZXhhbXBsZSJ9.a-vdiRCDSIlZdm-gRIk4dxfvsHT90W6a-Lt9JiGF4CMJCrLgl0zZAI57rjTRZXGd3PB0tAoZ8dM0OUQTOIxORkdvQlPYpvM_fEppcYfRkwUO8n7iswsvS4GqSJgotacf",
			},
			wantErr: true,
		},
		{
			name: "valid",
			fields: fields{
				supportedAlgorithms: types.StringArray([]string{"ES384"}),
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
			if err := v.Verify(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

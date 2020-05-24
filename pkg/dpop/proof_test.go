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

package dpop

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/square/go-jose/v3"
)

var (
	publicKey = mustJWK([]byte(`{
		"kty": "EC",
		"use": "sig",
		"crv": "P-256",
		"x": "wqoF5hz6iA2Zi2fA7hGdy0alu0-XGr3WDMeDH7MnrBU",
		"y": "ddvcizAhPkapK_CnlMLh139XljlSCssrj2M6y7ypeFw",
		"alg": "ES256"
	}`))
	privateKey = mustJWK([]byte(`{
		"kty": "EC",
		"d": "kPamR6LJ3aHNgKlGgs0HeMiAJx8zVJW5MHzLx7getc8",
		"use": "sig",
		"crv": "P-256",
		"x": "wqoF5hz6iA2Zi2fA7hGdy0alu0-XGr3WDMeDH7MnrBU",
		"y": "ddvcizAhPkapK_CnlMLh139XljlSCssrj2M6y7ypeFw",
		"alg": "ES256"
	}`))
)

func mustJWK(body []byte) *jose.JSONWebKey {
	var key jose.JSONWebKey
	if err := json.Unmarshal(body, &key); err != nil {
		panic(err)
	}
	return &key
}

func mustURLParse(value string) *url.URL {
	u, err := url.Parse(value)
	if err != nil {
		panic(err)
	}
	return u
}

func TestProof(t *testing.T) {
	type args struct {
		privateKey *jose.JSONWebKey
		htm        string
		htu        *url.URL
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "empty key",
			args: args{
				privateKey: &jose.JSONWebKey{},
				htm:        http.MethodPost,
				htu:        mustURLParse("https://server.example.com/token"),
			},
			wantErr: true,
		},
		{
			name: "public key",
			args: args{
				privateKey: publicKey,
				htm:        http.MethodPost,
				htu:        mustURLParse("https://server.example.com/token"),
			},
			wantErr: true,
		},
		{
			name: "htm empty",
			args: args{
				privateKey: privateKey,
				htm:        "",
				htu:        mustURLParse("https://server.example.com/token"),
			},
			wantErr: true,
		},
		{
			name: "htu nil",
			args: args{
				privateKey: privateKey,
				htm:        http.MethodPost,
				htu:        nil,
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				privateKey: privateKey,
				htm:        http.MethodPost,
				htu:        mustURLParse("https://server.example.com/token"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Proof(tt.args.privateKey, tt.args.htm, tt.args.htu)
			if (err != nil) != tt.wantErr {
				t.Errorf("Proof() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

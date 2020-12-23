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
	"testing"

	"github.com/square/go-jose/v3"
	"zntr.io/solid/pkg/sdk/jwk"
)

func Test_defaultSigner_Sign(t *testing.T) {
	type fields struct {
		tokenType   string
		alg         jose.SignatureAlgorithm
		keyProvider jwk.KeyProviderFunc
	}
	type args struct {
		ctx    context.Context
		claims interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &defaultSigner{
				tokenType:   tt.fields.tokenType,
				alg:         tt.fields.alg,
				keyProvider: tt.fields.keyProvider,
			}
			got, err := ds.Sign(tt.args.ctx, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("defaultSigner.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

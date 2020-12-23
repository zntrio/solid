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
	"reflect"
	"testing"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/sdk/types"
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &defaultVerifier{
				keySetProvider:      tt.fields.keySetProvider,
				supportedAlgorithms: tt.fields.supportedAlgorithms,
			}
			got, err := v.Parse(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("defaultVerifier.Parse() = %v, want %v", got, tt.want)
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
		// TODO: Add test cases.
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

func Test_defaultVerifier_Claims(t *testing.T) {
	type fields struct {
		keySetProvider      jwk.KeySetProviderFunc
		supportedAlgorithms types.StringArray
	}
	type args struct {
		raw    string
		claims interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &defaultVerifier{
				keySetProvider:      tt.fields.keySetProvider,
				supportedAlgorithms: tt.fields.supportedAlgorithms,
			}
			if err := v.Claims(tt.args.raw, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Claims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

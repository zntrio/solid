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
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"zntr.io/solid/pkg/sdk/jwt"
	jwtmock "zntr.io/solid/pkg/sdk/jwt/mock"
)

func TestDefaultProver(t *testing.T) {
	type args struct {
		signer jwt.Signer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "valid signer",
			args: args{
				signer: jwtmock.NewMockSigner(nil),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DefaultProver(tt.args.signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("DefaultProver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_defaultProver_Prove(t *testing.T) {
	type fields struct {
		signer jwt.Signer
	}
	type args struct {
		htm string
		htu string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*jwtmock.MockSigner)
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank htm",
			args: args{
				htm: "",
			},
			wantErr: true,
		},
		{
			name: "blank htu",
			args: args{
				htm: "GET",
				htu: "",
			},
			wantErr: true,
		},
		{
			name: "invalid htu",
			args: args{
				htm: "GET",
				htu: "https//server.com/resource",
			},
			wantErr: true,
		},
		{
			name: "invalid htm",
			args: args{
				htm: "POUET",
				htu: "https://server.com/resource",
			},
			wantErr: true,
		},
		{
			name: "token signature error",
			args: args{
				htm: "POST",
				htu: "https://server.com/resource",
			},
			prepare: func(signer *jwtmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				htm: "POST",
				htu: "https://server.com/resource",
			},
			prepare: func(signer *jwtmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockSigner := jwtmock.NewMockSigner(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockSigner)
			}

			p, _ := DefaultProver(mockSigner)
			got, err := p.Prove(tt.args.htm, tt.args.htu)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultProver.Prove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("defaultProver.Prove() = %v, want %v", got, tt.want)
			}
		})
	}
}

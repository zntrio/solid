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

package jwsreq

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/sdk/token"
	tokenmock "zntr.io/solid/sdk/token/mock"
)

var cmpOpts = []cmp.Option{
	cmpopts.IgnoreUnexported(wrappers.StringValue{}),
	cmpopts.IgnoreUnexported(corev1.AuthorizationRequest{}),
	cmpopts.IgnoreUnexported(corev1.Error{}),
}

func Test_jwtDecoder_Decode(t *testing.T) {
	type fields struct {
		verifier token.Verifier
	}
	type args struct {
		ctx   context.Context
		value string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*tokenmock.MockVerifier)
		want    *corev1.AuthorizationRequest
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank token",
			args: args{
				value: "",
			},
			wantErr: true,
		},
		{
			name: "claims error",
			args: args{
				value: "fake-token",
			},
			prepare: func(verifier *tokenmock.MockVerifier) {
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "claims json error",
			args: args{
				value: "fake-token",
			},
			prepare: func(verifier *tokenmock.MockVerifier) {
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *map[string]any:
						*v = map[string]any{
							"non-serializable": make(chan struct{}),
						}
					}
				}).Return(nil)
			},
			wantErr: true,
		},
		{
			name: "claims protojson error",
			args: args{
				value: "fake-token",
			},
			prepare: func(verifier *tokenmock.MockVerifier) {
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *map[string]any:
						*v = map[string]any{
							"scope": "openid",
							"foo":   "non-existent",
						}
					}
				}).Return(nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				value: "fake-token",
			},
			prepare: func(verifier *tokenmock.MockVerifier) {
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *map[string]any:
						*v = map[string]any{
							"scope": "openid",
						}
					}
				}).Return(nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationRequest{
				Scope: "openid",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockVerifier := tokenmock.NewMockVerifier(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockVerifier)
			}

			d := AuthorizationRequestDecoder(mockVerifier)
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

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

package device

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/oidc"
	generatormock "zntr.io/solid/sdk/generator/mock"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

var cmpOpts = []cmp.Option{cmpopts.IgnoreUnexported(flowv1.DeviceAuthorizationRequest{}), cmpopts.IgnoreUnexported(flowv1.DeviceAuthorizationResponse{}), cmpopts.IgnoreUnexported(flowv1.DeviceCodeValidationResponse{}), cmpopts.IgnoreUnexported(corev1.Error{})}

func Test_service_Device(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.DeviceAuthorizationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockDeviceCodeSession, *generatormock.MockDeviceCode, *generatormock.MockDeviceUserCode, *storagemock.MockUserCodeAttempts)
		want    *flowv1.DeviceAuthorizationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{},
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer: "",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty client id",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client nil error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "grant type not supported",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.UnsupportedGrantType().Build(),
			},
		},
		{
			name: "device code session registration error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSession, mdc *generatormock.MockDeviceCode, mduc *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				mdc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", nil)
				mduc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("WDJB-MJHT", nil)
				deviceCodes.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(uint64(60), fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.DeviceAuthorizationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
					Scope:    new("openid admin"),
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSession, mdc *generatormock.MockDeviceCode, mduc *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				mdc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", nil)
				mduc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("WDJB-MJHT", nil)
				deviceCodes.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Do(func(ctx context.Context, issuer, userCode string, session *sessionv1.DeviceCodeSession) {
					if session.ExpiresAt == 0 {
						t.Error("registered session ExpiresAt must not be zero")
					}
					if session.Status != sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING {
						t.Errorf("registered session Status = %v, want AUTHORIZATION_PENDING", session.Status)
					}
				}).Return(uint64(120), nil)
			},
			wantErr: false,
			want: &flowv1.DeviceAuthorizationResponse{
				Issuer:     "https://honest.as.example.com",
				DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
				UserCode:   "WDJB-MJHT",
				ExpiresIn:  120,
				Interval:   5,
			},
		},
		{
			name: "valid - offline_access stripped",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
					Scope:    new("openid offline_access admin"),
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSession, mdc *generatormock.MockDeviceCode, mduc *generatormock.MockDeviceUserCode, _ *storagemock.MockUserCodeAttempts) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				mdc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", nil)
				mduc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("WDJB-MJHT", nil)
				deviceCodes.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Do(func(ctx context.Context, issuer, userCode string, session *sessionv1.DeviceCodeSession) {
					if session.Scope == nil || *session.Scope != "openid admin" {
						t.Errorf("registered session Scope = %v, want 'openid admin' (offline_access stripped)", session.Scope)
					}
				}).Return(uint64(120), nil)
			},
			wantErr: false,
			want: &flowv1.DeviceAuthorizationResponse{
				Issuer:     "https://honest.as.example.com",
				DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
				UserCode:   "WDJB-MJHT",
				ExpiresIn:  120,
				Interval:   5,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientReader(ctrl)
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)
			deviceCodes := generatormock.NewMockDeviceCode(ctrl)
			userCodes := generatormock.NewMockDeviceUserCode(ctrl)
			userCodeAttempts := storagemock.NewMockUserCodeAttempts(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, deviceCodeSessions, deviceCodes, userCodes, userCodeAttempts)
			}

			// Prepare service
			underTest := New(clients, deviceCodeSessions, deviceCodes, userCodes, userCodeAttempts)

			// Do the request
			got, err := underTest.Authorize(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Device() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Device() res =%s", diff)
			}
		})
	}
}

func Test_service_DeviceValidate(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.DeviceCodeValidationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockDeviceCodeSession, *storagemock.MockUserCodeAttempts)
		want    *flowv1.DeviceCodeValidationResponse
		wantErr bool
	}{
		{
			name: "throttle trip - access_denied without session lookup",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "attacker-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), "https://honest.as.example.com\x00attacker-1").Return(uint64(5))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.AccessDenied().Build(),
			},
		},
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer: "",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty user_code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer: "https://honest.as.example.com",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty subject",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "session storage error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(nil, fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil session",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(nil, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "session nil request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "session nil client",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "expired session",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 1,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.TokenExpired().Build(),
			},
		},
		{
			name: "illegal state transition",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "session persist error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "session delete error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(nil)
				sessions.EXPECT().Delete(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "unknown user code records failure",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WRONG-CODE",
					Subject:  "attacker-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(0))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WRONG-CODE").Return(nil, storage.ErrNotFound)
				attempts.EXPECT().Fail(gomock.Any(), gomock.Any(), userCodeAttemptWindow).Return(uint64(1))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "success resets failure counter",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
					Subject:  "user-1",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, attempts *storagemock.MockUserCodeAttempts) {
				attempts.EXPECT().Failures(gomock.Any(), gomock.Any()).Return(uint64(4))
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId:   "s6BhdRkqt3",
						GrantTypes: []string{oidc.GrantTypeDeviceCode},
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(nil)
				sessions.EXPECT().Delete(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(nil)
				attempts.EXPECT().Reset(gomock.Any(), gomock.Any())
			},
			wantErr: false,
			want:    &flowv1.DeviceCodeValidationResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)
			userCodeAttempts := storagemock.NewMockUserCodeAttempts(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(deviceCodeSessions, userCodeAttempts)
			}

			// Prepare service
			underTest := New(nil, deviceCodeSessions, nil, nil, userCodeAttempts)

			// Do the request
			got, err := underTest.Validate(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Validate() res =%s", diff)
			}
		})
	}
}

func Test_service_DeviceDeny(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.DeviceCodeValidationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockDeviceCodeSession)
		want    *flowv1.DeviceCodeValidationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer: "",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty user_code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer: "https://honest.as.example.com",
				},
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "session storage error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession) {
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(nil, fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			// RFC 8628 section 5.1: the deny path is deliberately not
			// throttled; an unknown user_code is an invalid_request without
			// any failure recording.
			name: "unknown user code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WRONG-CODE",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession) {
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WRONG-CODE").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil session",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession) {
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(nil, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "illegal state transition",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession) {
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "persist error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession) {
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.DeviceCodeValidationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "success",
			args: args{
				ctx: context.Background(),
				req: &flowv1.DeviceCodeValidationRequest{
					Issuer:   "https://honest.as.example.com",
					UserCode: "WDJB-MJHT",
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession) {
				sessions.EXPECT().GetByUserCode(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).
					Do(func(_ context.Context, _, _ string, session *sessionv1.DeviceCodeSession) {
						if session.Status != sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_DENIED {
							t.Errorf("persisted session Status = %v, want DENIED", session.Status)
						}
					}).Return(nil)
			},
			wantErr: false,
			want:    &flowv1.DeviceCodeValidationResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)
			userCodeAttempts := storagemock.NewMockUserCodeAttempts(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(deviceCodeSessions)
			}

			// Prepare service
			underTest := New(nil, deviceCodeSessions, nil, nil, userCodeAttempts)

			// Do the request
			got, err := underTest.Deny(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Deny() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Deny() res =%s", diff)
			}
		})
	}
}

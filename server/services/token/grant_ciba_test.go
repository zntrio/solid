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

package token

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_ciba(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *clientv1.Client
		req    *flowv1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockBackchannelAuthenticationSession, *storagemock.MockToken, *tokenmock.MockGenerator, *tokenmock.MockGenerator)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil request",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil grant",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeCIBA,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req: &flowv1.TokenRequest{
					Issuer:    "",
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.UnauthorizedClient().Build(),
			},
		},
		{
			name: "authorization_details rejected",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType:            oidc.GrantTypeCIBA,
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{{Type: "payment"}},
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidAuthorizationDetails().Build(),
			},
		},
		{
			name: "dpop-bound client without proof",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes:            []string{oidc.GrantTypeCIBA},
					ClientId:              "s6BhdRkqt3",
					DpopBoundAccessTokens: true,
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					TokenConfirmation: nil,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "auth_req_id is blank",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "unknown auth_req_id",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, storage.ErrNotFound)
			},
			// CIBA section 11 mandates invalid_grant for an unknown
			// auth_req_id (unlike RFC 8628's invalid_request).
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "wrong client session",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "attacker",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "attacker"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "attacker",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					Subject:   new("user1"),
				}, nil)
			},
			// CIBA section 11: a session bound to another client is an
			// invalid auth_req_id for this one -> invalid_grant.
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "expired auth_req_id",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1000, 0) }
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					Subject:   new("user1"),
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.TokenExpired().Build(),
			},
		},
		{
			name: "authorization pending on admissible poll",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt:    200,
					Status:       sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
					LastPolledAt: 2,
					PollInterval: 5,
				}, nil)
				sessions.EXPECT().UpdateByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).Return(nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.AuthorizationPending().Build(),
			},
		},
		{
			name: "slow_down on fast polling",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt:    200,
					Status:       sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
					LastPolledAt: 8,
					PollInterval: 5,
				}, nil)
				sessions.EXPECT().UpdateByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).
					Do(func(_ context.Context, _, _ string, r *sessionv1.BackchannelAuthenticationSession) {
						if r.PollInterval != 10 {
							t.Errorf("persisted PollInterval = %d, want 10", r.PollInterval)
						}
					}).Return(nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.Slowdown().Build(),
			},
		},
		{
			name: "access denied",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_DENIED,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.AccessDenied().Build(),
			},
		},
		{
			name: "dpop-bound session without proof confirmation",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					TokenConfirmation: nil,
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					Subject:   new("user1"),
					// RFC 9449 section 10: session bound to a DPoP key.
					Confirmation: &tokenv1.TokenConfirmation{Jkt: "bound-jkt"},
				}, nil)
			},
			// The rejection happens before the consume: no minted token.
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "dpop-bound session with mismatched proof key",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					// A proof was presented, but for another key.
					TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "attacker-jkt"},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					Subject:   new("user1"),
					Confirmation: &tokenv1.TokenConfirmation{Jkt: "bound-jkt"},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "dpop-bound session with matching proof key",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "bound-jkt"},
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				session := &sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					Subject:   new("user1"),
					Confirmation: &tokenv1.TokenConfirmation{Jkt: "bound-jkt"},
				}
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().DeleteAndGetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
						ClientId:  "s6BhdRkqt3",
						Subject:   "user1",
					},
					// The confirmation rides the minted token (sender-constrained).
					Confirmation: &tokenv1.TokenConfirmation{Jkt: "bound-jkt"},
					Value:        "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: nil,
			},
		},
		{
			name: "valid - access token only, offline_access stripped",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeCIBA},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
					GrantType: oidc.GrantTypeCIBA,
					Grant: &flowv1.TokenRequest_Ciba{
						Ciba: &flowv1.GrantCIBA{
							ClientId:  "s6BhdRkqt3",
							AuthReqId: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					Scope: new("openid offline_access"),
				},
			},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				session := &sessionv1.BackchannelAuthenticationSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.BackchannelAuthenticationRequest{
						ClientId: "s6BhdRkqt3",
						Scope:    new("openid offline_access"),
					},
					ExpiresAt: 200,
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					Subject:   new("user1"),
					Scope:     new("openid offline_access"),
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{
						{Type: "payment_initiation"},
					},
				}
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().DeleteAndGetByAuthReqID(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Do(func(_ context.Context, tk *tokenv1.Token) {
					if tk.Metadata.Scope != "openid" {
						t.Errorf("token meta Scope = %q, want 'openid' (offline_access stripped)", tk.Metadata.Scope)
					}
					if len(tk.Metadata.AuthorizationDetails) != 1 || tk.Metadata.AuthorizationDetails[0].Type != "payment_initiation" {
						t.Errorf("token meta AuthorizationDetails = %v, want session details carried", tk.Metadata.AuthorizationDetails)
					}
				}).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				// RFC 9700 section 4.12.2: the CIBA grant never mints
				// refresh tokens; offline_access is stripped.
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
						Scope:     "openid",
						ClientId:  "s6BhdRkqt3",
						Subject:   "user1",
						AuthorizationDetails: []*tokenv1.AuthorizationDetail{
							{Type: "payment_initiation"},
						},
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			sessions := storagemock.NewMockBackchannelAuthenticationSession(ctrl)
			accessTokens := tokenmock.NewMockGenerator(ctrl)
			refreshTokens := tokenmock.NewMockGenerator(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(sessions, tokens, accessTokens, refreshTokens)
			}

			s := &service{
				backchannelSessions: sessions,
				tokens:              tokens,
				accessTokenGen:      accessTokens,
				refreshTokenGen:     refreshTokens,
			}
			got, err := s.ciba(tt.args.ctx, tt.args.client, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.ciba() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.ciba() res = %s", diff)
			}
		})
	}
}

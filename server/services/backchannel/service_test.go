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

package backchannel

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
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	generatormock "zntr.io/solid/sdk/generator/mock"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

var cmpOpts = []cmp.Option{
	cmpopts.IgnoreUnexported(flowv1.BackchannelAuthenticationRequest{}),
	cmpopts.IgnoreUnexported(flowv1.BackchannelAuthenticationResponse{}),
	cmpopts.IgnoreUnexported(flowv1.BackchannelAuthenticationValidationResponse{}),
	cmpopts.IgnoreUnexported(corev1.Error{}),
	// protovalidate generates the syntactic-level descriptions; their
	// exact wording is not the protocol contract, the error code is.
	cmpopts.IgnoreFields(corev1.Error{}, "ErrorDescription"),
}

func cibaClient() *clientv1.Client {
	return &clientv1.Client{
		ClientId:   "s6BhdRkqt3",
		GrantTypes: []string{oidc.GrantTypeCIBA},
	}
}

func validRequest() *flowv1.BackchannelAuthenticationRequest {
	return &flowv1.BackchannelAuthenticationRequest{
		Issuer:         "https://honest.as.example.com",
		ClientId:       "s6BhdRkqt3",
		Scope:          new("openid profile"),
		LoginHint:      new("hello"),
		BindingMessage: new("W4SCT"),
	}
}

func newService(t *testing.T) (*service, *storagemock.MockClientReader, *storagemock.MockBackchannelAuthenticationSession, *generatormock.MockAuthReqID) {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	clients := storagemock.NewMockClientReader(ctrl)
	sessions := storagemock.NewMockBackchannelAuthenticationSession(ctrl)
	authReqIDs := generatormock.NewMockAuthReqID(ctrl)
	hints := HintResolverFunc(func(_ context.Context, req *flowv1.BackchannelAuthenticationRequest) (string, error) {
		if req.GetLoginHint() == "unknown-user" {
			return "", fmt.Errorf("unknown user")
		}
		return req.GetLoginHint(), nil
	})
	underTest := New(clients, sessions, authReqIDs, hints, authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}), []string{"ES256"}).(*service)

	return underTest, clients, sessions, authReqIDs
}

func Test_service_Authorize(t *testing.T) {
	tests := []struct {
		name    string
		req     *flowv1.BackchannelAuthenticationRequest
		prepare func(clients *storagemock.MockClientReader, sessions *storagemock.MockBackchannelAuthenticationSession, authReqIDs *generatormock.MockAuthReqID)
		want    *flowv1.BackchannelAuthenticationResponse
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name:    "empty request",
			req:     &flowv1.BackchannelAuthenticationRequest{},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name:    "empty issuer",
			req:     &flowv1.BackchannelAuthenticationRequest{ClientId: "s6BhdRkqt3"},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name:    "empty client id",
			req:     &flowv1.BackchannelAuthenticationRequest{Issuer: "https://honest.as.example.com"},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "client not found",
			req:  validRequest(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidClient().Build()},
		},
		{
			name: "client storage error",
			req:  validRequest(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.ServerError().Build()},
		},
		{
			name: "unauthorized client",
			req:  validRequest(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				}, nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.UnauthorizedClient().Build()},
		},
		{
			name: "multiple hints",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.IdTokenHint = new("foo")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "no hint",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.LoginHint = nil
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "missing binding message",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.BindingMessage = nil
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidBindingMessage().Build()},
		},
		{
			name: "malformed binding message",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.BindingMessage = new("$£ not ok")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidBindingMessage().Build()},
		},
		{
			name: "missing openid scope",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.Scope = new("profile")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidScope().Build()},
		},
		{
			name: "unknown user",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.LoginHint = new("unknown-user")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.UnknownUserID().Build()},
		},
		{
			name: "unsupported authorization details",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.AuthorizationDetails = []*tokenv1.AuthorizationDetail{{Type: "unknown-type"}}
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidAuthorizationDetails().Build()},
		},
		{
			name: "registration error",
			req:  validRequest(),
			prepare: func(clients *storagemock.MockClientReader, sessions *storagemock.MockBackchannelAuthenticationSession, authReqIDs *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
				authReqIDs.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
				sessions.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", gomock.Any()).Return(uint64(300), fmt.Errorf("foo"))
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.ServerError().Build()},
		},
		{
			name: "valid",
			req:  validRequest(),
			prepare: func(clients *storagemock.MockClientReader, sessions *storagemock.MockBackchannelAuthenticationSession, authReqIDs *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
				authReqIDs.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
				sessions.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", gomock.Any()).Do(func(_ context.Context, _ string, _ string, session *sessionv1.BackchannelAuthenticationSession) {
					if session.ExpiresAt == 0 {
						t.Error("registered session ExpiresAt must not be zero")
					}
					if session.Status != sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING {
						t.Errorf("registered session Status = %v, want PENDING", session.Status)
					}
					if session.Subject == nil || *session.Subject != "hello" {
						t.Errorf("registered session Subject = %v, want 'hello'", session.Subject)
					}
					if session.PollInterval != 5 {
						t.Errorf("registered session PollInterval = %d, want 5", session.PollInterval)
					}
				}).Return(uint64(300), nil)
			},
			wantErr: false,
			want: &flowv1.BackchannelAuthenticationResponse{
				Issuer:    "https://honest.as.example.com",
				AuthReqId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ExpiresIn: 300,
				Interval:  5,
			},
		},
		{
			name: "valid with requested expiry",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.RequestedExpiry = new(uint64(900))
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, sessions *storagemock.MockBackchannelAuthenticationSession, authReqIDs *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
				authReqIDs.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
				sessions.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", gomock.Any()).Do(func(_ context.Context, _ string, _ string, session *sessionv1.BackchannelAuthenticationSession) {
					want := uint64(timeFunc().Add(900 * time.Second).Unix())
					if session.ExpiresAt != want {
						t.Errorf("registered session ExpiresAt = %d, want %d", session.ExpiresAt, want)
					}
				}).Return(uint64(900), nil)
			},
			wantErr: false,
			want: &flowv1.BackchannelAuthenticationResponse{
				Issuer:    "https://honest.as.example.com",
				AuthReqId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ExpiresIn: 900,
				Interval:  5,
			},
		},
		{
			name: "valid - dpop_jkt bound to session",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.DpopJkt = new("0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, sessions *storagemock.MockBackchannelAuthenticationSession, authReqIDs *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
				authReqIDs.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
				sessions.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", gomock.Any()).Do(func(_ context.Context, _ string, _ string, session *sessionv1.BackchannelAuthenticationSession) {
					if session.Confirmation == nil || session.Confirmation.Jkt != "0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8" {
						t.Errorf("registered session Confirmation = %v, want the bound jkt (RFC 9449 section 10 binding)", session.Confirmation)
					}
				}).Return(uint64(300), nil)
			},
			wantErr: false,
			want: &flowv1.BackchannelAuthenticationResponse{
				Issuer:    "https://honest.as.example.com",
				AuthReqId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ExpiresIn: 300,
				Interval:  5,
			},
		},
		{
			name: "valid - offline_access stripped",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.Scope = new("openid offline_access admin")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, sessions *storagemock.MockBackchannelAuthenticationSession, authReqIDs *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
				authReqIDs.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
				sessions.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", gomock.Any()).Do(func(_ context.Context, _ string, _ string, session *sessionv1.BackchannelAuthenticationSession) {
					if session.Scope == nil || *session.Scope != "openid admin" {
						t.Errorf("registered session Scope = %v, want 'openid admin' (offline_access stripped)", session.Scope)
					}
				}).Return(uint64(300), nil)
			},
			wantErr: false,
			want: &flowv1.BackchannelAuthenticationResponse{
				Issuer:    "https://honest.as.example.com",
				AuthReqId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ExpiresIn: 300,
				Interval:  5,
			},
		},
		{
			name: "request parameter set alongside another parameter",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.Request = new("foo.bar.baz")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "invalid signed request (malformed JWT)",
			req: func() *flowv1.BackchannelAuthenticationRequest {
				r := validRequest()
				r.LoginHint = nil
				r.Scope = nil
				r.BindingMessage = nil
				r.Request = new("not-a-jwt")
				return r
			}(),
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockBackchannelAuthenticationSession, _ *generatormock.MockAuthReqID) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(cibaClient(), nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underTest, clients, sessions, authReqIDs := newService(t)
			if tt.prepare != nil {
				tt.prepare(clients, sessions, authReqIDs)
			}

			got, err := underTest.Authorize(context.Background(), tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Authorize() res =%s", diff)
			}
		})
	}
}

func Test_service_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *flowv1.BackchannelAuthenticationValidationRequest
		prepare func(sessions *storagemock.MockBackchannelAuthenticationSession)
		want    *flowv1.BackchannelAuthenticationValidationResponse
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name:    "empty issuer",
			req:     &flowv1.BackchannelAuthenticationValidationRequest{AuthReqId: "aaa", Subject: "hello"},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name:    "empty auth_req_id",
			req:     &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", Subject: "hello"},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name:    "empty subject",
			req:     &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa"},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "unknown auth_req_id",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "expired auth_req_id",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(&sessionv1.BackchannelAuthenticationSession{
					Issuer:    "https://honest.as.example.com",
					AuthReqId: "aaa",
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
					ExpiresAt: 1,
					Request:   &flowv1.BackchannelAuthenticationRequest{},
					Client:    cibaClient(),
				}, nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.TokenExpired().Build()},
		},
		{
			name: "already validated (no replay)",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(&sessionv1.BackchannelAuthenticationSession{
					Issuer:    "https://honest.as.example.com",
					AuthReqId: "aaa",
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED,
					ExpiresAt: ^uint64(0),
					Request:   &flowv1.BackchannelAuthenticationRequest{},
					Client:    cibaClient(),
				}, nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "valid",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(&sessionv1.BackchannelAuthenticationSession{
					Issuer:    "https://honest.as.example.com",
					AuthReqId: "aaa",
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
					ExpiresAt: ^uint64(0),
					Request:   &flowv1.BackchannelAuthenticationRequest{},
					Client:    cibaClient(),
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "aaa", gomock.Any()).Do(func(_ context.Context, _ string, _ string, session *sessionv1.BackchannelAuthenticationSession) {
					if session.Status != sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_VALIDATED {
						t.Errorf("stored session Status = %v, want VALIDATED", session.Status)
					}
					if session.Subject == nil || *session.Subject != "hello" {
						t.Errorf("stored session Subject = %v, want 'hello'", session.Subject)
					}
				}).Return(nil)
				sessions.EXPECT().Delete(gomock.Any(), "https://honest.as.example.com", "aaa").Return(nil)
			},
			wantErr: false,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underTest, _, sessions, _ := newService(t)
			if tt.prepare != nil {
				tt.prepare(sessions)
			}

			got, err := underTest.Validate(context.Background(), tt.req)
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

func Test_service_Deny(t *testing.T) {
	tests := []struct {
		name    string
		req     *flowv1.BackchannelAuthenticationValidationRequest
		prepare func(sessions *storagemock.MockBackchannelAuthenticationSession)
		want    *flowv1.BackchannelAuthenticationValidationResponse
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "unknown auth_req_id",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "already denied (no replay)",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(&sessionv1.BackchannelAuthenticationSession{
					Issuer:    "https://honest.as.example.com",
					AuthReqId: "aaa",
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_DENIED,
					ExpiresAt: ^uint64(0),
					Request:   &flowv1.BackchannelAuthenticationRequest{},
					Client:    cibaClient(),
				}, nil)
			},
			wantErr: true,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{Error: rfcerrors.InvalidRequest().Build()},
		},
		{
			name: "valid deny",
			req:  &flowv1.BackchannelAuthenticationValidationRequest{Issuer: "https://honest.as.example.com", AuthReqId: "aaa", Subject: "hello"},
			prepare: func(sessions *storagemock.MockBackchannelAuthenticationSession) {
				sessions.EXPECT().GetByAuthReqID(gomock.Any(), "https://honest.as.example.com", "aaa").Return(&sessionv1.BackchannelAuthenticationSession{
					Issuer:    "https://honest.as.example.com",
					AuthReqId: "aaa",
					Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
					ExpiresAt: ^uint64(0),
					Request:   &flowv1.BackchannelAuthenticationRequest{},
					Client:    cibaClient(),
				}, nil)
				sessions.EXPECT().Validate(gomock.Any(), "https://honest.as.example.com", "aaa", gomock.Any()).Do(func(_ context.Context, _ string, _ string, session *sessionv1.BackchannelAuthenticationSession) {
					if session.Status != sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_DENIED {
						t.Errorf("stored session Status = %v, want DENIED", session.Status)
					}
				}).Return(nil)
			},
			wantErr: false,
			want:    &flowv1.BackchannelAuthenticationValidationResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underTest, _, sessions, _ := newService(t)
			if tt.prepare != nil {
				tt.prepare(sessions)
			}

			got, err := underTest.Deny(context.Background(), tt.req)
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

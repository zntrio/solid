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
	"errors"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	sdkidjag "zntr.io/solid/sdk/idjag"
	idjagmock "zntr.io/solid/sdk/idjag/mock"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	storagemock "zntr.io/solid/server/storage/mock"
)

// -----------------------------------------------------------------------------
// jwt-bearer grant fixtures

const (
	jwtBearerTestIssuer = "https://resource-as.example/"
	jwtBearerClientID   = "client-at-resource-as"
)

// jwtBearerClient assembles an authenticated client with jwt-bearer capability.
func jwtBearerClient() *clientv1.Client {
	return &clientv1.Client{
		ClientId:   jwtBearerClientID,
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes: []string{oidc.GrantTypeJWTBearer},
	}
}

// jwtBearerRequest builds a TokenRequest for the jwt-bearer grant.
func jwtBearerRequest(scope string) *flowv1.TokenRequest {
	req := &flowv1.TokenRequest{
		Issuer:    jwtBearerTestIssuer,
		Client:    &clientv1.Client{ClientId: jwtBearerClientID},
		GrantType: oidc.GrantTypeJWTBearer,
		Grant: &flowv1.TokenRequest_JwtBearer{
			JwtBearer: &flowv1.GrantJWTBearer{
				Assertion: "assertion",
			},
		},
	}
	if scope != "" {
		req.Scope = &scope
	}
	return req
}

// validIDJAGClaims assembles a fully valid ID-JAG claim set for this AS.
func validIDJAGClaims(now time.Time) *tokenv1.IdentityAssertionJWTAuthorizationGrant {
	return &tokenv1.IdentityAssertionJWTAuthorizationGrant{
		Iss:      "https://idp.example/",
		Sub:      "subject-1",
		Aud:      jwtBearerTestIssuer,
		ClientId: jwtBearerClientID,
		Jti:      "jti-1",
		Exp:      uint64(now.Add(5 * time.Minute).Unix()), //nolint:gosec // unix time
		Iat:      uint64(now.Unix()),                      //nolint:gosec // unix time
	}
}

func Test_service_jwtBearer(t *testing.T) {
	now := time.Now()

	t.Run("redeems a valid ID-JAG", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.Scope = new(string)
		*claims.Scope = "chat.read"

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("at-value", nil)
		tokens.EXPECT().Create(gomock.Any(), jwtBearerTestIssuer, gomock.Any()).Return(nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest("chat.read"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
		if res.AccessToken == nil {
			t.Fatal("expected access token in response")
		}
		if res.AccessToken.Metadata.Subject != "subject-1" {
			t.Errorf("subject = %q, want subject-1", res.AccessToken.Metadata.Subject)
		}
	})

	t.Run("rejects client_id mismatch", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)

		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.ClientId = "other-client"

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidGrant().Build().Err {
			t.Errorf("expected invalid_grant, got %+v", res.Error)
		}
	})

	t.Run("rejects key-bound ID-JAG without matching proof", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)

		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.CnfJkt = new(string)
		*claims.CnfJkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidGrant().Build().Err {
			t.Errorf("expected invalid_grant, got %+v", res.Error)
		}
	})

	t.Run("accepts key-bound ID-JAG with matching proof", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.CnfJkt = new(string)
		*claims.CnfJkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

		req := jwtBearerRequest("")
		req.TokenConfirmation = &tokenv1.TokenConfirmation{
			Jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		}

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("at-value", nil)
		tokens.EXPECT().Create(gomock.Any(), jwtBearerTestIssuer, gomock.Any()).Return(nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
		if res.AccessToken.Confirmation == nil || res.AccessToken.Confirmation.Jkt != *claims.CnfJkt {
			t.Errorf("access token not DPoP-bound to the ID-JAG key")
		}
	})

	t.Run("rejects invalid ID-JAG from verifier", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)

		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil,
			WithIDJAGVerifier(verifier)).(*service)

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(nil, sdkidjag.ErrInvalidGrant)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidGrant().Build().Err {
			t.Errorf("expected invalid_grant, got %+v", res.Error)
		}
	})

	t.Run("rejects scope exceeding the grant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)

		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.Scope = new(string)
		*claims.Scope = "chat.read"

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest("chat.read admin.write"))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidScope().Build().Err {
			t.Errorf("expected invalid_scope, got %+v", res.Error)
		}
	})

	t.Run("fails closed without configured verifier", func(t *testing.T) {
		svc := New(nil, nil, nil, nil, nil, nil, nil, nil).(*service)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.UnsupportedGrantType().Build().Err {
			t.Errorf("expected unsupported_grant_type, got %+v", res.Error)
		}
	})
}

func Test_service_jwtBearer_authorizationDetails(t *testing.T) {
	now := time.Now()

	grantedDetails := []*tokenv1.AuthorizationDetail{
		{Type: "payment_initiation", Actions: []string{"initiate"}, Locations: []string{"https://api.example.com/payments"}},
	}

	t.Run("narrows granted authorization_details", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.AuthorizationDetails = grantedDetails

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("at-value", nil)
		tokens.EXPECT().Create(gomock.Any(), jwtBearerTestIssuer, gomock.Any()).Return(nil)

		req := jwtBearerRequest("")
		req.AuthorizationDetails = grantedDetails
		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
		if len(res.AccessToken.Metadata.AuthorizationDetails) != 1 {
			t.Fatalf("expected the granted details on the access token, got %v", res.AccessToken.Metadata.AuthorizationDetails)
		}
	})

	t.Run("carries grant details when the request has none", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.AuthorizationDetails = grantedDetails

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("at-value", nil)
		tokens.EXPECT().Create(gomock.Any(), jwtBearerTestIssuer, gomock.Any()).Return(nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
		if len(res.AccessToken.Metadata.AuthorizationDetails) != 1 {
			t.Fatalf("expected the granted details carried over, got %v", res.AccessToken.Metadata.AuthorizationDetails)
		}
	})

	t.Run("rejects authorization_details exceeding the grant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)

		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)

		req := jwtBearerRequest("")
		req.AuthorizationDetails = grantedDetails
		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidScope().Build().Err {
			t.Errorf("expected invalid_scope, got %+v", res.Error)
		}
	})

	t.Run("audience falls back to the first resource", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.Resource = []string{"https://api.chat.example/"}

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, tok *tokenv1.Token) (string, error) {
				if tok.Metadata.Audience != "https://api.chat.example/" {
					t.Errorf("audience = %q, want the resource identifier", tok.Metadata.Audience)
				}
				return "at-value", nil
			})
		tokens.EXPECT().Create(gomock.Any(), jwtBearerTestIssuer, gomock.Any()).Return(nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
	})
}

func Test_service_jwtBearer_edgeCases(t *testing.T) {
	now := time.Now()
	timeFunc = func() time.Time { return now }

	t.Run("rejects nil client", func(t *testing.T) {
		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil).(*service)
		res, err := svc.jwtBearer(context.Background(), nil, jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.ServerError().Build().Err {
			t.Errorf("expected server_error, got %+v", res.Error)
		}
	})

	t.Run("rejects client without jwt-bearer capability", func(t *testing.T) {
		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil).(*service)
		capless := &clientv1.Client{ClientId: jwtBearerClientID, ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL, GrantTypes: []string{oidc.GrantTypeClientCredentials}}

		res, err := svc.jwtBearer(context.Background(), capless, jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.UnauthorizedClient().Build().Err {
			t.Errorf("expected unauthorized_client, got %+v", res.Error)
		}
	})

	t.Run("rejects nil grant", func(t *testing.T) {
		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil).(*service)
		req := &flowv1.TokenRequest{
			Issuer:    jwtBearerTestIssuer,
			Client:    &clientv1.Client{ClientId: jwtBearerClientID},
			GrantType: oidc.GrantTypeJWTBearer,
		}

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidRequest().Build().Err {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects access token generation failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.Scope = new(string)
		*claims.Scope = "chat.read"

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", errors.New("generation failure"))

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.ServerError().Build().Err {
			t.Errorf("expected server_error, got %+v", res.Error)
		}
	})

	t.Run("reports narrowed scope in the response", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		generator := tokenmock.NewMockGenerator(ctrl)
		tokens := storagemock.NewMockToken(ctrl)

		svc := NewWithOptions(generator, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGVerifier(verifier)).(*service)

		claims := validIDJAGClaims(now)
		claims.Scope = new(string)
		*claims.Scope = "chat.read chat.history"

		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(claims, nil)
		generator.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("at-value", nil)
		tokens.EXPECT().Create(gomock.Any(), jwtBearerTestIssuer, gomock.Any()).Return(nil)

		res, err := svc.jwtBearer(context.Background(), jwtBearerClient(), jwtBearerRequest("chat.read"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
		if res.Scope == nil || *res.Scope != "chat.read" {
			t.Errorf("response scope = %v, want the narrowed chat.read", res.Scope)
		}
	})

	t.Run("Token dispatch routes jwt-bearer", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		verifier := idjagmock.NewMockVerifier(ctrl)
		clients := storagemock.NewMockClientReader(ctrl)

		svc := NewWithOptions(nil, nil, clients, nil, nil, nil, nil, nil,
			WithIDJAGVerifier(verifier)).(*service)

		clients.EXPECT().Get(gomock.Any(), jwtBearerClientID).Return(jwtBearerClient(), nil)
		verifier.EXPECT().Verify(gomock.Any(), "assertion").Return(nil, sdkidjag.ErrInvalidGrant)

		res, err := svc.Token(context.Background(), jwtBearerRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Err != rfcerrors.InvalidGrant().Build().Err {
			t.Errorf("expected invalid_grant, got %+v", res.Error)
		}
	})
}

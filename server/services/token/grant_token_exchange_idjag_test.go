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
	idjagmock "zntr.io/solid/sdk/idjag/mock"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

// -----------------------------------------------------------------------------
// ID-JAG issuance fixtures

const (
	idjagTestIssuer   = "https://idp.example/"
	idjagClientID     = "wiki-client"
	idjagTargetIssuer = "https://chat.example/"
	idjagTargetClient = "chat-client-id"
)

// staticAudienceResolver resolves a single trusted target.
type staticAudienceResolver struct {
	target *IDJAGResourceServer
}

func (r *staticAudienceResolver) Resolve(_ context.Context, audience string) (*IDJAGResourceServer, error) {
	if audience != r.target.Issuer {
		return nil, errors.New("unknown audience")
	}
	return r.target, nil
}

// staticSubjectResolver resolves subjects pairwise-style.
type staticSubjectResolver struct{}

func (staticSubjectResolver) Resolve(_ context.Context, claims *SubjectTokenClaims, _ *IDJAGResourceServer) (*IDJAGSubjectResolution, error) {
	return &IDJAGSubjectResolution{
		Subject:  "pairwise-subject-1",
		AuthTime: claims.AuthTime,
		ACR:      claims.ACR,
	}, nil
}

// idjagIssuanceHarness assembles the service wired for ID-JAG issuance.
type idjagIssuanceHarness struct {
	service *service
	signer  *idjagmock.MockSigner
	tokens  *storagemock.MockToken
}

func newIDJAGIssuanceHarness(t *testing.T) *idjagIssuanceHarness {
	t.Helper()
	ctrl := gomock.NewController(t)

	signer := idjagmock.NewMockSigner(ctrl)
	tokens := storagemock.NewMockToken(ctrl)
	audience := &staticAudienceResolver{
		target: &IDJAGResourceServer{
			Issuer: idjagTargetIssuer,
			ClientIDMapping: map[string]string{
				idjagClientID: idjagTargetClient,
			},
		},
	}

	svc := NewWithOptions(nil, nil, nil, nil, nil, nil, tokens, nil,
		WithIDJAGIssuance(signer, audience, staticSubjectResolver{})).(*service)

	return &idjagIssuanceHarness{service: svc, signer: signer, tokens: tokens}
}

// idjagClient assembles a token-exchange capable client.
func idjagClient() *clientv1.Client {
	return &clientv1.Client{ClientId: idjagClientID, GrantTypes: []string{oidc.GrantTypeTokenExchange}}
}

// idjagIssuanceRequest builds a Token Exchange request for an ID-JAG.
func idjagIssuanceRequest(scope string) *flowv1.TokenRequest {
	tokenType := oidc.IDJAGTokenType
	req := &flowv1.TokenRequest{
		Issuer:    idjagTestIssuer,
		Client:    &clientv1.Client{ClientId: idjagClientID},
		GrantType: oidc.GrantTypeTokenExchange,
		Audience:  new(string),
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				RequestedTokenType: &tokenType,
				SubjectToken:       "refresh-token-value",
				SubjectTokenType:   oidc.TokenExchangeRefreshTokenType,
			},
		},
	}
	*req.Audience = idjagTargetIssuer
	if scope != "" {
		req.Scope = &scope
	}
	return req
}

// idjagRefreshToken assembles a stored active refresh token.
func idjagRefreshToken(now time.Time) *tokenv1.Token {
	return &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
		Value:     "refresh-token-value",
		Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			Issuer:    idjagTestIssuer,
			Subject:   "user-1",
			ClientId:  idjagClientID,
			IssuedAt:  uint64(now.Add(-time.Hour).Unix()), //nolint:gosec // unix time
			ExpiresAt: uint64(now.Add(time.Hour).Unix()),  //nolint:gosec // unix time
			Scope:     "chat.read chat.history",
		},
	}
}

func Test_service_tokenExchangeIDJAG(t *testing.T) {
	// Freeze the package clock: tests in this package override timeFunc
	// without restoring it, so this suite must not depend on the real
	// wall clock either.
	now := time.Now()
	timeFunc = func() time.Time { return now }

	t.Run("issues an ID-JAG from a valid refresh token", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("chat.read")

		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(idjagRefreshToken(now), nil)
		h.signer.EXPECT().Serialize(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, claims *tokenv1.IdentityAssertionJWTAuthorizationGrant) (string, error) {
				// Assert the minted claim set.
				if claims.Iss != idjagTestIssuer {
					t.Errorf("iss = %q", claims.Iss)
				}
				if claims.Aud != idjagTargetIssuer {
					t.Errorf("aud = %q", claims.Aud)
				}
				if claims.ClientId != idjagTargetClient {
					t.Errorf("client_id = %q, want the target-mapped identifier", claims.ClientId)
				}
				if claims.Sub != "pairwise-subject-1" {
					t.Errorf("sub = %q", claims.Sub)
				}
				if claims.Scope == nil || *claims.Scope != "chat.read" {
					t.Errorf("scope = %v", claims.Scope)
				}
				return "idjag-jwt", nil
			})

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
		if res.AccessToken == nil || res.AccessToken.Value != "idjag-jwt" {
			t.Fatal("expected the ID-JAG JWT in the access_token field")
		}
		if res.IssuedTokenType == nil || *res.IssuedTokenType != oidc.IDJAGTokenType {
			t.Fatal("expected issued_token_type=id-jag")
		}
	})

	t.Run("rejects unknown audience", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")
		*req.Audience = "https://evil.example/"

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidTarget().Build().Error {
			t.Errorf("expected invalid_target, got %+v", res.Error)
		}
	})

	t.Run("rejects missing audience", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")
		req.Audience = nil

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects expired subject refresh token", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")

		expired := idjagRefreshToken(now)
		expired.Metadata.ExpiresAt = uint64(now.Add(-time.Minute).Unix()) //nolint:gosec // unix time
		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(expired, nil)

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects subject token bound to another client", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")

		foreign := idjagRefreshToken(now)
		foreign.Metadata.ClientId = "other-client"
		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(foreign, nil)

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects scope exceeding the subject context", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("admin.write")

		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(idjagRefreshToken(now), nil)

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidScope().Build().Error {
			t.Errorf("expected invalid_scope, got %+v", res.Error)
		}
	})

	t.Run("rejects id_token subject tokens in this iteration", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")
		req.GetTokenExchange().SubjectTokenType = oidc.TokenExchangeIDTokenType

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects unknown subject token in storage", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")

		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(nil, storage.ErrNotFound)

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("binds cnf.jkt from the DPoP proof", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")
		req.TokenConfirmation = &tokenv1.TokenConfirmation{Jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}

		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(idjagRefreshToken(now), nil)
		h.signer.EXPECT().Serialize(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, claims *tokenv1.IdentityAssertionJWTAuthorizationGrant) (string, error) {
				if claims.CnfJkt == nil || *claims.CnfJkt != "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" {
					t.Errorf("cnf.jkt = %v, want the DPoP proof thumbprint", claims.CnfJkt)
				}
				return "idjag-jwt", nil
			})

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
	})
}

func Test_service_tokenExchangeIDJAG_coverage(t *testing.T) {
	now := time.Now()
	timeFunc = func() time.Time { return now }

	t.Run("fails closed when issuance roles are unwired", func(t *testing.T) {
		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, nil, nil).(*service)

		res, err := svc.tokenExchange(context.Background(), idjagClient(), idjagIssuanceRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects authorization_details", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")
		req.AuthorizationDetails = []*tokenv1.AuthorizationDetail{{Type: "payment_initiation"}}

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidAuthorizationDetails().Build().Error {
			t.Errorf("expected invalid authorization_details error, got %+v", res.Error)
		}
	})

	t.Run("rejects subject resolver failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		tokens := storagemock.NewMockToken(ctrl)
		failingSubjects := &staticSubjectResolverError{}

		audience := &staticAudienceResolver{
			target: &IDJAGResourceServer{
				Issuer:          idjagTargetIssuer,
				ClientIDMapping: map[string]string{idjagClientID: idjagTargetClient},
			},
		}
		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGIssuance(idjagmock.NewMockSigner(ctrl), audience, failingSubjects)).(*service)

		tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(idjagRefreshToken(now), nil)

		res, err := svc.tokenExchange(context.Background(), idjagClient(), idjagIssuanceRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidGrant().Build().Error {
			t.Errorf("expected invalid_grant, got %+v", res.Error)
		}
	})

	t.Run("rejects inactive subject refresh token", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		revoked := idjagRefreshToken(now)
		revoked.Status = tokenv1.TokenStatus_TOKEN_STATUS_REVOKED
		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(revoked, nil)

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), idjagIssuanceRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidRequest().Build().Error {
			t.Errorf("expected invalid_request, got %+v", res.Error)
		}
	})

	t.Run("rejects storage failure on subject lookup", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(nil, errors.New("storage down"))

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), idjagIssuanceRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.ServerError().Build().Error {
			t.Errorf("expected server_error, got %+v", res.Error)
		}
	})

	t.Run("carries resource and auth context claims", func(t *testing.T) {
		h := newIDJAGIssuanceHarness(t)
		req := idjagIssuanceRequest("")
		req.Resource = []string{"https://api.chat.example/"}

		rt := idjagRefreshToken(now)
		authTime := uint64(now.Add(-time.Minute).Unix()) //nolint:gosec // unix time
		acr := "phrh"
		rt.Metadata.AuthTime = &authTime
		rt.Metadata.Acr = &acr
		h.tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(rt, nil)
		h.signer.EXPECT().Serialize(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, claims *tokenv1.IdentityAssertionJWTAuthorizationGrant) (string, error) {
				if len(claims.Resource) != 1 || claims.Resource[0] != "https://api.chat.example/" {
					t.Errorf("resource = %v", claims.Resource)
				}
				if claims.AuthTime == nil {
					t.Error("auth_time not carried over from the subject token")
				}
				if claims.Acr == nil || *claims.Acr != "phrh" {
					t.Errorf("acr = %v", claims.Acr)
				}
				return "idjag-jwt", nil
			})

		res, err := h.service.tokenExchange(context.Background(), idjagClient(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Error != nil {
			t.Fatalf("unexpected protocol error: %+v", res.Error)
		}
	})

	t.Run("rejects unmapped client", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		tokens := storagemock.NewMockToken(ctrl)
		audience := &staticAudienceResolver{
			target: &IDJAGResourceServer{
				Issuer:          idjagTargetIssuer,
				ClientIDMapping: map[string]string{}, // no mapping for the client
			},
		}
		svc := NewWithOptions(nil, nil, nil, nil, nil, nil, tokens, nil,
			WithIDJAGIssuance(idjagmock.NewMockSigner(ctrl), audience, staticSubjectResolver{})).(*service)

		tokens.EXPECT().GetByValue(gomock.Any(), idjagTestIssuer, "refresh-token-value").Return(idjagRefreshToken(now), nil)

		res, err := svc.tokenExchange(context.Background(), idjagClient(), idjagIssuanceRequest(""))
		if err == nil {
			t.Fatal("expected error, got none")
		}
		if res.Error == nil || res.Error.Error != rfcerrors.InvalidGrant().Build().Error {
			t.Errorf("expected invalid_grant for unmapped client, got %+v", res.Error)
		}
	})
}

// staticSubjectResolverError always fails subject resolution.
type staticSubjectResolverError struct{}

func (staticSubjectResolverError) Resolve(_ context.Context, _ *SubjectTokenClaims, _ *IDJAGResourceServer) (*IDJAGSubjectResolution, error) {
	return nil, errors.New("subject resolution failure")
}

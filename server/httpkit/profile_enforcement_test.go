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

package httpkit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// The strict application-type profile constrains clients whose
// application_type maps to a profile entry; other clients fall back to
// their registration metadata.

// newProfileTestClient registers a client with the given application type
// and returns it.
func newProfileTestClient(t *testing.T, clients storage.Client, applicationType string) *clientv1.Client {
	t.Helper()

	id, err := clients.Register(context.Background(), &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ApplicationType:         applicationType,
		ClientName:              "profile-test-client",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})
	require.NoError(t, err)

	client, err := clients.Get(context.Background(), id)
	require.NoError(t, err)
	return client
}

// profileTokenRequest builds a token-endpoint POST with the injected
// client in the context (standing in for the client-authentication
// middleware).
func profileTokenRequest(t *testing.T, client *clientv1.Client, grantType string) *http.Request {
	t.Helper()

	form := url.Values{"grant_type": {grantType}}
	req := httptest.NewRequest(http.MethodPost, "https://as.example.org/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(clientauthentication.Inject(req.Context(), client))
}

// TestProfileTokenHandlerRejectsGrantOutsideProfile asserts the token
// handler rejects a grant_type outside the client's application-type
// profile with 400 unauthorized_client.
func TestProfileTokenHandlerRejectsGrantOutsideProfile(t *testing.T) {
	clients := inmemory.Clients()
	// Service profile allows client_credentials only; request the
	// authorization_code grant.
	client := newProfileTestClient(t, clients, oidc.ApplicationTypeService)

	rec := httptest.NewRecorder()
	httpkit.Token("https://as.example.org", nopTokenService{}, nopDPoPVerifier{}, profile.Strict()).
		ServeHTTP(rec, profileTokenRequest(t, client, oidc.GrantTypeAuthorizationCode))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "unauthorized_client")
}

// TestProfileTokenHandlerAllowsUnconstrainedClient asserts a client without
// a profile-known application type passes through to the service. The
// grant is client_credentials: under the enforced DPoP posture the
// authorization_code grant always requires a proof, so only a non-code
// grant can exercise the pass-through path.
func TestProfileTokenHandlerAllowsUnconstrainedClient(t *testing.T) {
	clients := inmemory.Clients()
	// "cli" is not a strict profile entry: the client stays unconstrained.
	client := newProfileTestClient(t, clients, "cli")

	rec := httptest.NewRecorder()
	httpkit.Token("https://as.example.org", nopTokenService{}, nopDPoPVerifier{}, profile.Strict()).
		ServeHTTP(rec, profileTokenRequest(t, client, oidc.GrantTypeClientCredentials))

	require.NotEqual(t, http.StatusBadRequest, rec.Code,
		"client without profile-known application type must reach the service")
}

// nopTokenService is a services.Token whose Token() always succeeds with
// an empty response: profile tests only assert handler-level rejection.
type nopTokenService struct{}

func (nopTokenService) Token(_ context.Context, _ *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	return &flowv1.TokenResponse{
		AccessToken: &tokenv1.Token{
			Value: "opaque",
			Metadata: &tokenv1.TokenMeta{
				ExpiresAt: 4102444800, // 2100-01-01: far-future for the test
				Scope:     "openid",
			},
		},
	}, nil
}

func (nopTokenService) Introspect(_ context.Context, _ *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	return nil, nil
}

func (nopTokenService) Revoke(_ context.Context, _ *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	return nil, nil
}

// nopDPoPVerifier is a dpop.Verifier that accepts any proof with an empty
// thumbprint.
type nopDPoPVerifier struct{}

func (nopDPoPVerifier) Verify(_ context.Context, _, _, _ string, _ ...dpop.Option) (string, error) {
	return "", nil
}

// compile-time interface conformance.
var (
	_ services.Token = nopTokenService{}
	_ dpop.Verifier  = nopDPoPVerifier{}
)

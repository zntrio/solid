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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
)

// fakeToken is a minimal services.Token capturing the TokenRequest it
// receives and returning a fixed token response.
type fakeToken struct {
	req *flowv1.TokenRequest
}

func (f *fakeToken) Token(_ context.Context, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	f.req = req
	return &flowv1.TokenResponse{
		AccessToken: &tokenv1.Token{
			Value: "at-1",
			Metadata: &tokenv1.TokenMeta{
				ExpiresAt: 4102444800,
			},
		},
	}, nil
}

func (f *fakeToken) Introspect(context.Context, *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	return nil, nil
}

func (f *fakeToken) Revoke(context.Context, *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	return nil, nil
}

// TestTokenDecodesTokenExchangeGrant asserts the token endpoint maps every
// RFC 8693 section 2.1 form parameter onto the TokenExchange grant arm,
// including the optional parameters recorded only when present, plus the
// shared resource (audience), scope and authorization_details handling.
func TestTokenDecodesTokenExchangeGrant(t *testing.T) {
	fake := &fakeToken{}

	inner := httpkit.Token("https://as.example.org", fake, nil, profile.Strict())
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(clientauthentication.Inject(r.Context(), &clientv1.Client{ClientId: "client-1"}))
		inner.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type":  {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":         {"subject-token-value"},
		"subject_token_type":    {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":           {"actor-token-value"},
		"actor_token_type":      {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":              {"http://127.0.0.1:8085"},
		"scope":                 {"timestamp:read"},
		"authorization_details": {`[{"type":"mcp_tools","locations":["http://127.0.0.1:8085"],"actions":["timestamp:read"]}]`},
	}
	resp, err := srv.Client().PostForm(srv.URL, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "at-1", body["access_token"])

	require.NotNil(t, fake.req)
	require.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", fake.req.GrantType)

	grant := fake.req.GetTokenExchange()
	require.NotNil(t, grant, "TokenRequest must carry the TokenExchange grant arm")
	require.Equal(t, "subject-token-value", grant.SubjectToken)
	require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", grant.SubjectTokenType)
	require.NotNil(t, grant.RequestedTokenType)
	require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", *grant.RequestedTokenType)
	require.NotNil(t, grant.ActorToken)
	require.Equal(t, "actor-token-value", *grant.ActorToken)
	require.NotNil(t, grant.ActorTokenType)
	require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", *grant.ActorTokenType)

	// RFC 8707: resource becomes the audience of the issued token.
	require.NotNil(t, fake.req.Audience)
	require.Equal(t, "http://127.0.0.1:8085", *fake.req.Audience)

	require.NotNil(t, fake.req.Scope)
	require.Equal(t, "timestamp:read", *fake.req.Scope)

	// RFC 9396: authorization_details parse into the request message.
	require.Len(t, fake.req.AuthorizationDetails, 1)
	require.Equal(t, "mcp_tools", fake.req.AuthorizationDetails[0].Type)
	require.Equal(t, []string{"http://127.0.0.1:8085"}, fake.req.AuthorizationDetails[0].Locations)
	require.Equal(t, []string{"timestamp:read"}, fake.req.AuthorizationDetails[0].Actions)
}

// TestTokenDecodesTokenExchangeGrantMinimal asserts the optional RFC 8693
// parameters stay unset (nil pointers) when omitted, so the service can
// distinguish an omitted parameter from an empty value.
func TestTokenDecodesTokenExchangeGrantMinimal(t *testing.T) {
	fake := &fakeToken{}

	inner := httpkit.Token("https://as.example.org", fake, nil, profile.Strict())
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(clientauthentication.Inject(r.Context(), &clientv1.Client{ClientId: "client-1"}))
		inner.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"subject-token-value"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	resp, err := srv.Client().PostForm(srv.URL, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	grant := fake.req.GetTokenExchange()
	require.NotNil(t, grant)
	require.Equal(t, "subject-token-value", grant.SubjectToken)
	require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", grant.SubjectTokenType)
	require.Nil(t, grant.RequestedTokenType)
	require.Nil(t, grant.ActorToken)
	require.Nil(t, grant.ActorTokenType)
}

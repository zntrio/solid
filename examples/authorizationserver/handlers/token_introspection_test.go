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

package handlers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/examples/authorizationserver/handlers"
	"zntr.io/solid/server/clientauthentication"
)

// fakeIntrospectToken is a minimal services.Token returning a fixed
// introspection response.
type fakeIntrospectToken struct {
	res *tokenv1.IntrospectResponse
}

func (f *fakeIntrospectToken) Token(context.Context, *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	return nil, nil
}

func (f *fakeIntrospectToken) Introspect(context.Context, *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	return f.res, nil
}

func (f *fakeIntrospectToken) Revoke(context.Context, *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	return nil, nil
}

// TestTokenIntrospectionIncludesAuthorizationDetails asserts the
// introspection response of a details-carrying active token includes the
// authorization_details member with the RFC 9396 section 9.2 shape (top
// level, array of objects with type and actions).
func TestTokenIntrospectionIncludesAuthorizationDetails(t *testing.T) {
	details := []*tokenv1.AuthorizationDetail{
		{
			Type:    "payment_initiation",
			Actions: []string{"initiate"},
		},
	}
	fake := &fakeIntrospectToken{
		res: &tokenv1.IntrospectResponse{
			Token: &tokenv1.Token{
				TokenId: "tid-1",
				Status:  tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
				Metadata: &tokenv1.TokenMeta{
					Issuer:               "https://as.example.org",
					Subject:              "user-1",
					ClientId:             "client-1",
					Audience:             "aud",
					NotBefore:            1,
					ExpiresAt:            4102444800,
					AuthorizationDetails: details,
				},
			},
		},
	}

	// Wrap the handler to inject an authenticated client, standing in for
	// the client-authentication middleware.
	inner := handlers.TokenIntrospection("https://as.example.org", fake)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(clientauthentication.Inject(r.Context(), &clientv1.Client{ClientId: "client-1"}))
		inner.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := srv.Client().PostForm(srv.URL, url.Values{"token": {"opaque-token-value"}})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, true, body["active"])

	v, ok := body["authorization_details"]
	require.True(t, ok, "authorization_details missing from introspection response")
	arr, isArr := v.([]any)
	require.True(t, isArr, "authorization_details must be a JSON array")
	require.Len(t, arr, 1)

	entry, isObj := arr[0].(map[string]any)
	require.True(t, isObj)
	require.Equal(t, "payment_initiation", entry["type"])
	actions, isActions := entry["actions"].([]any)
	require.True(t, isActions)
	require.Equal(t, "initiate", actions[0])
	require.True(t, strings.Contains(strings.ToLower(http.StatusText(http.StatusOK)), "ok"))
}

// TestTokenIntrospectionRendersX5tS256Cnf asserts the introspection response
// of an RFC 8705 certificate-bound token carries the cnf member with the
// exact "x5t#S256" member name (not the proto field name) and stays labeled
// as a Bearer token (an mTLS-bound token is constrained at the TLS layer,
// not a DPoP token).
func TestTokenIntrospectionRendersX5tS256Cnf(t *testing.T) {
	fake := &fakeIntrospectToken{
		res: &tokenv1.IntrospectResponse{
			Token: &tokenv1.Token{
				TokenId: "tid-2",
				Status:  tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
				Metadata: &tokenv1.TokenMeta{
					Issuer:    "https://as.example.org",
					Subject:   "user-1",
					ClientId:  "client-1",
					Audience:  "aud",
					NotBefore: 1,
					ExpiresAt: 4102444800,
				},
				Confirmation: &tokenv1.TokenConfirmation{
					X5TS256: "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0",
				},
			},
		},
	}

	inner := handlers.TokenIntrospection("https://as.example.org", fake)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(clientauthentication.Inject(r.Context(), &clientv1.Client{ClientId: "client-1"}))
		inner.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := srv.Client().PostForm(srv.URL, url.Values{"token": {"opaque-token-value"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rawBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, string(rawBody), `"x5t#S256":"A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0"`)
	require.NotContains(t, string(rawBody), `"x5t_s256"`)
	require.Contains(t, string(rawBody), `"token_type":"Bearer"`)
	require.NotContains(t, string(rawBody), `"token_type":"DPoP"`)
}

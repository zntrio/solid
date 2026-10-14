// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/types"
)

// fakeIntrospectionClient is a client.Client whose introspection
// endpoint returns a fixed token state, so the example RS middleware's
// RFC 6750 challenge emission can be driven end-to-end over HTTP.
type fakeIntrospectionClient struct {
	token *tokenv1.Token
}

func (f *fakeIntrospectionClient) Assertion() (string, error) { return "assertion", nil }
func (f *fakeIntrospectionClient) PublicKeys(_ context.Context) (jwk.Set, uint64, error) {
	var set jwk.Set // nil set: never consulted by the RS middleware
	return set, 0, nil
}
func (f *fakeIntrospectionClient) ServerMetadata() *discoveryv1.ServerMetadata {
	return &discoveryv1.ServerMetadata{}
}
func (f *fakeIntrospectionClient) Introspect(_ context.Context, _, _ string) (*tokenv1.Token, error) {
	return f.token, nil
}
func (f *fakeIntrospectionClient) ClientCredentials(_ context.Context, _ string) (*client.Token, error) {
	return nil, nil
}

// compile-time interface check.
var _ client.Client = (*fakeIntrospectionClient)(nil)

// bearerChallenge drives the example RS Authorizer over a real
// httptest server with the given introspection result and returns the
// response.
func bearerChallenge(t *testing.T, tok *tokenv1.Token) *http.Response {
	t.Helper()

	cli := &fakeIntrospectionClient{token: tok}
	handler := Authorizer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "timestamp:read", cli, nil, 0)

	srv := httptest.NewServer(handler)
	t.Cleanup(func() { srv.Close() })

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/temperature", nil) //nolint:noctx // test
	require.NoError(t, err)
	if tok != nil {
		req.Header.Set("Authorization", "Bearer thetoken")
	}

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// TestRFC6750_ChallengeNoToken drives the missing-token path: RFC 6750
// section 3 requires a Bearer challenge on 401 for a request without
// credentials.
func TestRFC6750_ChallengeNoToken(t *testing.T) {
	res := bearerChallenge(t, nil)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	wa := res.Header.Get("WWW-Authenticate")
	require.True(t, strings.HasPrefix(wa, `Bearer `), "challenge must use the Bearer auth-scheme: %q", wa)
	require.Contains(t, wa, `error="invalid_request"`)
}

// TestRFC6750_ChallengeInvalidToken drives the inactive-token path: the
// challenge carries error="invalid_token" with the 401 of section 3.1.
func TestRFC6750_ChallengeInvalidToken(t *testing.T) {
	res := bearerChallenge(t, &tokenv1.Token{
		Status: tokenv1.TokenStatus_TOKEN_STATUS_EXPIRED,
	})
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	wa := res.Header.Get("WWW-Authenticate")
	require.True(t, strings.HasPrefix(wa, `Bearer `), "challenge must use the Bearer auth-scheme: %q", wa)
	require.Contains(t, wa, `error="invalid_token"`)
}

// TestRFC6750_ChallengeInsufficientScope drives the scope gate: section
// 3.1's insufficient_scope error with the 403 and the scope attribute.
func TestRFC6750_ChallengeInsufficientScope(t *testing.T) {
	res := bearerChallenge(t, &tokenv1.Token{
		Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			ClientId: "t8p9duw4n2klximkv3kagaud796ul67g",
			Subject:  "user-1",
			Scope:    "openid profile", // lacks timestamp:read
			Audience: resourceMetadataURI,
		},
	})
	require.Equal(t, http.StatusForbidden, res.StatusCode)
	wa := res.Header.Get("WWW-Authenticate")
	require.True(t, strings.HasPrefix(wa, `Bearer `), "challenge must use the Bearer auth-scheme: %q", wa)
	require.Contains(t, wa, `error="insufficient_scope"`)
	require.Contains(t, wa, `scope="timestamp:read"`)
}

// TestRFC6750_ChallengeAudienceMismatch drives the RFC 8707 audience
// gate in front of the Bearer path: a token minted for another resource
// server is invalid_token here.
func TestRFC6750_ChallengeAudienceMismatch(t *testing.T) {
	res := bearerChallenge(t, &tokenv1.Token{
		Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			ClientId: "t8p9duw4n2klximkv3kagaud796ul67g",
			Subject:  "user-1",
			Scope:    "timestamp:read",
			Audience: "https://other-rs.example.com",
		},
	})
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	wa := res.Header.Get("WWW-Authenticate")
	require.Contains(t, wa, `error="invalid_token"`)
}

// TestRFC6750_ChallengeStepUp drives the RFC 9470 leg of the same gate
// function: a required ACR with a token carrying none fails closed with
// insufficient_user_authentication.
func TestRFC6750_ChallengeStepUp(t *testing.T) {
	cli := &fakeIntrospectionClient{token: &tokenv1.Token{
		Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			ClientId: "t8p9duw4n2klximkv3kagaud796ul67g",
			Subject:  "user-1",
			Scope:    "timestamp:read",
			Audience: resourceMetadataURI,
		},
	}}
	handler := Authorizer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "timestamp:read", cli, types.StringArray{"urn:solid:loa:2fa:any"}, 0)

	srv := httptest.NewServer(handler)
	t.Cleanup(func() { srv.Close() })

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/temperature", nil) //nolint:noctx // test
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer thetoken")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	wa := res.Header.Get("WWW-Authenticate")
	require.Contains(t, wa, `error="insufficient_user_authentication"`)
	require.Contains(t, wa, "acr_values=")
}

// TestRFC6750_SuccessHappyPath drives the full gate chain with a
// compliant token: 200, no challenge.
func TestRFC6750_SuccessHappyPath(t *testing.T) {
	res := bearerChallenge(t, &tokenv1.Token{
		Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			ClientId: "t8p9duw4n2klximkv3kagaud796ul67g",
			Subject:  "user-1",
			Scope:    "timestamp:read",
			Audience: resourceMetadataURI,
		},
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Empty(t, res.Header.Get("WWW-Authenticate"))
}

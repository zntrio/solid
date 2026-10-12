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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services"
)

// fakeAuthorization is a minimal services.Authorization capturing the
// AuthorizeRequest it receives and returning a fixed authorization code
// response.
type fakeAuthorization struct {
	req *flowv1.AuthorizeRequest
}

func (f *fakeAuthorization) Register(context.Context, *flowv1.RegistrationRequest) (*flowv1.RegistrationResponse, error) {
	return nil, nil
}

func (f *fakeAuthorization) Authorize(_ context.Context, req *flowv1.AuthorizeRequest) (*flowv1.AuthorizeResponse, error) {
	f.req = req
	return &flowv1.AuthorizeResponse{
		RedirectUri:  "http://127.0.0.1:8100/callback",
		Code:         "splg/o3op8zLBvfD2eW2rVSJn8PSgTCGtiYWQD",
		State:        req.Request.GetState(),
		ResponseMode: "query",
		Issuer:       "https://as.example.org",
		ClientId:     "client-1",
	}, nil
}

// fakePairwiseEncoder is a no-op pairwise encoder.
type fakePairwiseEncoder struct{}

func (fakePairwiseEncoder) Encode(_, sub string) (string, error) { return sub, nil }

// fakeClients is a minimal storage.ClientReader with a fixed client.
type fakeClients struct{}

func (fakeClients) Get(context.Context, string) (*clientv1.Client, error) {
	return &clientv1.Client{ClientId: "client-1"}, nil
}

func (fakeClients) GetByName(context.Context, string) (*clientv1.Client, error) {
	return &clientv1.Client{ClientId: "client-1"}, nil
}

// newAuthorizationTestServer assembles the /authorize handler exactly the
// way examples/authorizationserver wires it: security headers, then the demo
// Basic resource-owner login standing in for the user agent.
func newAuthorizationTestServer(t *testing.T, authz services.Authorization) *httptest.Server {
	t.Helper()

	inner := httpkit.Authorization(
		"https://as.example.org",
		authz,
		fakeClients{},
		nil, // jarmEncoder: unused, plain query response
		fakePairwiseEncoder{},
		nil, // requestObjectAlgorithms: no by-value request object in these tests
		profile.Strict(),
	)
	basicAuth := httpkit.BasicAuthentication(func(u, p string) (string, *httpkit.AuthenticationEvent, bool) {
		if u == "hello" && p == "world" {
			return u, &httpkit.AuthenticationEvent{
				ACR:      "urn:solid:loa:1fa:any",
				AuthTime: uint64(time.Now().Unix()), //nolint:gosec // unix time is non-negative
			}, true
		}
		return "", nil, false
	})
	srv := httptest.NewServer(httpkit.Adapt(inner, httpkit.SecurityHeaders(), basicAuth))
	t.Cleanup(srv.Close)
	return srv
}

// TestAuthorizationConsumesPARRequestURI asserts the authorization endpoint
// forwards a request_uri parameter to the service as the request reference
// (RFC 9126), without attempting a by-value JAR decode, and carries the
// Basic-authenticated subject.
func TestAuthorizationConsumesPARRequestURI(t *testing.T) {
	authz := &fakeAuthorization{}
	srv := newAuthorizationTestServer(t, authz)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"?client_id=client-1&request_uri=urn:solid:par-1", nil)
	require.NoError(t, err)
	req.SetBasicAuth("hello", "world")
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// The service received the request reference, not a decoded request.
	require.NotNil(t, authz.req)
	require.NotNil(t, authz.req.Request)
	require.NotNil(t, authz.req.Request.RequestUri)
	require.Equal(t, "urn:solid:par-1", *authz.req.Request.RequestUri)
	require.Empty(t, authz.req.Request.ResponseType)
	require.Equal(t, "hello", authz.req.Subject)
}

// TestAuthorizationRejectsRequestAndRequestURI asserts the RFC 9101
// section 5 mutual exclusion of the request and request_uri parameters.
func TestAuthorizationRejectsRequestAndRequestURI(t *testing.T) {
	authz := &fakeAuthorization{}
	srv := newAuthorizationTestServer(t, authz)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"?client_id=client-1&request=jwt-value&request_uri=urn:solid:par-1", nil)
	require.NoError(t, err)
	req.SetBasicAuth("hello", "world")

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_request", body["error"])
	require.Nil(t, authz.req, "mutually exclusive parameters must not reach the service")
}

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

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/generator"
)

// RFC 9126 (Pushed Authorization Requests) adversarial coverage.

// TestRFC9126_GeneratedUriRoundTrip asserts the request_uri generator's own
// output satisfies its validator and survives a full Register -> Authorize
// round-trip (RFC 9126 section 2.1: the AS returns a request_uri).
func TestRFC9126_GeneratedUriRoundTrip(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})
	g := generator.DefaultRequestURI()

	uri, err := g.Generate(t.Context(), h.issuer)
	require.NoError(t, err)
	require.NoError(t, g.Validate(t.Context(), h.issuer, uri), "generated request_uri must satisfy its own validator")

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)

	// Push via the PAR register endpoint.
	rres, rerr := h.authz.Register(t.Context(), &flowv1.RegistrationRequest{
		Issuer:  h.issuer,
		Client:  client,
		Request: req,
	})
	require.NoError(t, rerr)
	require.Nil(t, rres.Error)
	require.NotEmpty(t, rres.RequestUri)

	// Authorize by reference.
	req.RequestUri = &rres.RequestUri
	ares, aerr := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.NoError(t, aerr)
	require.Nil(t, ares.Error)
	require.NotEmpty(t, ares.Code, "PAR round-trip must issue a code")

	// The code redeems.
	tres, terr := h.redeemCode(t, client.ClientId, ares.Code, verifier, testRedirectURI)
	require.NoError(t, terr)
	require.NotNil(t, tres.AccessToken)
}

// TestRFC9126_RequestUriSingleUse asserts a request_uri cannot be consumed
// twice (RFC 9126 section 2.2: burn after read).
func TestRFC9126_RequestUriSingleUse(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)

	rres, rerr := h.authz.Register(t.Context(), &flowv1.RegistrationRequest{
		Issuer:  h.issuer,
		Client:  client,
		Request: req,
	})
	require.NoError(t, rerr)
	require.NotEmpty(t, rres.RequestUri)

	authorize := func() (*flowv1.AuthorizeResponse, error) {
		r := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		r.RequestUri = &rres.RequestUri
		return h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
			Issuer:  h.issuer,
			Client:  client,
			Subject: "user-1",
			Request: r,
		})
	}

	// First use succeeds.
	ares, aerr := authorize()
	require.NoError(t, aerr)
	require.Nil(t, ares.Error)

	// Second use of the same request_uri fails.
	bres, berr := authorize()
	require.Error(t, berr, "request_uri must be single-use")
	require.NotNil(t, bres.Error)
	require.Equal(t, "invalid_request", bres.Error.Err)
}

// TestRFC9126_RequestUriClientBinding_2_2 asserts client B cannot consume a
// request_uri pushed by client A (RFC 9126 section 2.2: the pushed request
// is bound to the authenticated client that pushed it).
func TestRFC9126_RequestUriClientBinding_2_2(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})
	clientB := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(clientA.ClientId, verifier, testRedirectURI)

	rres, rerr := h.authz.Register(t.Context(), &flowv1.RegistrationRequest{
		Issuer:  h.issuer,
		Client:  clientA,
		Request: req,
	})
	require.NoError(t, rerr)
	require.NotEmpty(t, rres.RequestUri)

	// Attacker (client B) presents client A's request_uri.
	reqB := validAuthorizationRequest(clientB.ClientId, verifier, "https://client-b.example.org/cb")
	reqB.RequestUri = &rres.RequestUri
	bres, berr := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  clientB,
		Subject: "attacker",
		Request: reqB,
	})
	require.Error(t, berr, "request_uri must not be consumable by another client")
	require.NotNil(t, bres.Error)
	require.Equal(t, "invalid_request", bres.Error.Err)
}

// TestRFC9126_UnknownRequestUri asserts an unknown (expired or never
// issued) request_uri is rejected with invalid_request (RFC 9126 section
// 2.2; same storage path as a purged-after-expiry entry).
func TestRFC9126_UnknownRequestUri(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	uri := "urn:solid:" + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	req.RequestUri = &uri

	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err, "unknown request_uri must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
}

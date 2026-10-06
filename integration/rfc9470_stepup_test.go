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
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
)

// RFC 9470 adversarial coverage: step-up authentication round-trips —
// RS-style gates, acr_values/max_age enforcement at code issuance, and
// event propagation into minted tokens and introspection.

const (
	stepUpACR = "urn:solid:loa:1fa:any"
)

// stepUpEvent builds an AuthEvent with the given ACR and auth_time.
func stepUpEvent(acr string, authTime uint64) *tokenv1.AuthEvent {
	return &tokenv1.AuthEvent{Acr: &acr, AuthTime: &authTime}
}

// authorizeWithEvent drives the real Authorize service with an explicit
// login authentication event (mirroring seedAuthorization, which hardcodes
// a subject without event).
func (h *harness) authorizeWithEvent(t *testing.T, client *clientv1.Client, req *flowv1.AuthorizationRequest, ev *tokenv1.AuthEvent) (*flowv1.AuthorizeResponse, error) {
	t.Helper()

	ctx := t.Context()

	// Register the authorization request (PAR-style) with a well-formed
	// request_uri, as produced by generator.DefaultRequestURI.
	requestURI := "urn:solid:" + random.String(32)
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}
	req.RequestUri = new(string)
	*req.RequestUri = requestURI

	return h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:    h.issuer,
		Client:    client,
		Subject:   "user-1",
		Request:   req,
		AuthEvent: ev,
	})
}

// seedAuthorizationWithEvent authorizes with a login event and returns the
// code (fatal on failure).
func (h *harness) seedAuthorizationWithEvent(t *testing.T, client *clientv1.Client, req *flowv1.AuthorizationRequest, ev *tokenv1.AuthEvent) string {
	t.Helper()

	res, err := h.authorizeWithEvent(t, client, req, ev)
	if err != nil {
		t.Fatalf("unable to authorize: %v", err)
	}
	if res.Error != nil {
		t.Fatalf("authorization failed: %s", res.Error.Error)
	}
	if res.Code == "" {
		t.Fatal("authorization response has no code")
	}
	return res.Code
}

// TestRFC9470_StepUpHappyPathRoundTrip asserts an authorization request
// carrying acr_values/max_age with a matching login event mints tokens
// whose metadata carries acr/auth_time, surfaced by introspection
// (RFC 9470 section 6).
func TestRFC9470_StepUpHappyPathRoundTrip(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	maxAge := uint64(3600)
	req.MaxAge = &maxAge
	req.AcrValues = new(string)
	*req.AcrValues = stepUpACR

	authTime := uint64(time.Now().Unix())
	code := h.seedAuthorizationWithEvent(t, client, req, stepUpEvent(stepUpACR, authTime))

	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.NotNil(t, res.AccessToken.Metadata)
	require.NotNil(t, res.AccessToken.Metadata.Acr)
	require.Equal(t, stepUpACR, *res.AccessToken.Metadata.Acr)
	require.NotNil(t, res.AccessToken.Metadata.AuthTime)
	require.Equal(t, authTime, *res.AccessToken.Metadata.AuthTime)

	// Introspection surfaces both members (RFC 9470 section 6.2).
	ires, err := h.introspect(t, client.ClientId, res.AccessToken.Value)
	require.NoError(t, err)
	require.NotNil(t, ires.Token)
	require.NotNil(t, ires.Token.Metadata)
	require.NotNil(t, ires.Token.Metadata.Acr)
	require.Equal(t, stepUpACR, *ires.Token.Metadata.Acr)
	require.NotNil(t, ires.Token.Metadata.AuthTime)
	require.Equal(t, authTime, *ires.Token.Metadata.AuthTime)
}

// TestRFC9470_UnmeetableACRRejected asserts an acr_values request the
// login event cannot satisfy is refused with
// unmet_authentication_requirements and no code is issued (RFC 9470
// section 5).
func TestRFC9470_UnmeetableACRRejected(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.AcrValues = new(string)
	*req.AcrValues = "urn:solid:loa:2fa:hard"

	res, err := h.authorizeWithEvent(t, client, req, stepUpEvent(stepUpACR, uint64(time.Now().Unix())))
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, oidc.ErrorUnmetAuthenticationRequirements, res.Error.Error)
	require.Empty(t, res.Code)
}

// TestRFC9470_StaleLoginRejectedByMaxAge asserts a login older than the
// requested max_age is refused (RFC 9470 section 5: freshness).
func TestRFC9470_StaleLoginRejectedByMaxAge(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	maxAge := uint64(5)
	req.MaxAge = &maxAge

	staleAuthTime := uint64(time.Now().Add(-1 * time.Hour).Unix())
	res, err := h.authorizeWithEvent(t, client, req, stepUpEvent(stepUpACR, staleAuthTime))
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "unmet_authentication_requirements", res.Error.Error)
	require.Empty(t, res.Code)
}

// TestRFC9470_NoEventFailClosed asserts a step-up request without any
// recorded login event fails closed (no token mintable without a
// reference authentication event).
func TestRFC9470_NoEventFailClosed(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	maxAge := uint64(3600)
	req.MaxAge = &maxAge
	req.AcrValues = new(string)
	*req.AcrValues = stepUpACR

	res, err := h.authorizeWithEvent(t, client, req, nil)
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "unmet_authentication_requirements", res.Error.Error)
	require.Empty(t, res.Code)
}

// TestRFC9470_RefreshRotationPreservesEvent asserts acr/auth_time survive
// refresh token rotation: the values are established at user-authentication
// time and MUST NOT change on renewal (RFC 9470 section 6.1).
func TestRFC9470_RefreshRotationPreservesEvent(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.AcrValues = new(string)
	*req.AcrValues = stepUpACR

	authTime := uint64(time.Now().Unix())
	code := h.seedAuthorizationWithEvent(t, client, req, stepUpEvent(stepUpACR, authTime))

	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// Rotate.
	rres, err := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, err)
	require.NotNil(t, rres.AccessToken)
	require.NotNil(t, rres.AccessToken.Metadata)
	require.NotNil(t, rres.AccessToken.Metadata.Acr)
	require.Equal(t, stepUpACR, *rres.AccessToken.Metadata.Acr)
	require.NotNil(t, rres.AccessToken.Metadata.AuthTime)
	require.Equal(t, authTime, *rres.AccessToken.Metadata.AuthTime)
}

// TestRFC9470_Adversarial_MalformedEvents asserts degenerate events are
// rejected rather than minting tokens an RS would keep challenging: an
// empty ACR is a member of no requested acr_values, and a zero auth_time
// cannot evidence freshness (RFC 9470 section 5 fail-closed posture).
func TestRFC9470_Adversarial_MalformedEvents(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	t.Run("empty acr string", func(t *testing.T) {
		verifier, _ := newPKCEPair(t)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.AcrValues = new(string)
		*req.AcrValues = stepUpACR

		res, err := h.authorizeWithEvent(t, client, req, stepUpEvent("", uint64(time.Now().Unix())))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "unmet_authentication_requirements", res.Error.Error)
		require.Empty(t, res.Code)
	})

	t.Run("zero auth_time with max_age", func(t *testing.T) {
		verifier, _ := newPKCEPair(t)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		maxAge := uint64(3600)
		req.MaxAge = &maxAge

		res, err := h.authorizeWithEvent(t, client, req, stepUpEvent(stepUpACR, 0))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "unmet_authentication_requirements", res.Error.Error)
		require.Empty(t, res.Code)
	})
}

// TestRFC9470_PARPushCarryingAcrValuesNotRejectedAtPushTime asserts a
// pushed authorization request carrying acr_values is accepted at
// registration (no login event exists yet — enforcement belongs to code
// issuance, RFC 9126 section 2.2 / RFC 9470 section 4), and that consuming
// it applies the step-up check against the pushed request content
// (request_uri swap).
func TestRFC9470_PARPushCarryingAcrValuesNotRejectedAtPushTime(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	// Push a request carrying acr_values via the real Register (PAR).
	verifier, _ := newPKCEPair(t)
	pushed := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	pushed.AcrValues = new(string)
	*pushed.AcrValues = stepUpACR

	pres, err := h.authz.Register(t.Context(), &flowv1.RegistrationRequest{
		Issuer:  h.issuer,
		Client:  client,
		Request: pushed,
	})
	require.NoError(t, err)
	require.Nil(t, pres.Error)
	require.NotEmpty(t, pres.RequestUri)

	// Consume the pushed request by reference with a matching event:
	// success, and the minted token carries the event.
	authTime := uint64(time.Now().Unix())
	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: &flowv1.AuthorizationRequest{
			RequestUri: &pres.RequestUri,
		},
		AuthEvent: stepUpEvent(stepUpACR, authTime),
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotEmpty(t, res.Code)

	tres, err := h.redeemCode(t, client.ClientId, res.Code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, tres.AccessToken.Metadata.Acr)
	require.Equal(t, stepUpACR, *tres.AccessToken.Metadata.Acr)

	// Push a second request whose acr_values do NOT match the event.
	verifier2, _ := newPKCEPair(t)
	pushed2 := validAuthorizationRequest(client.ClientId, verifier2, testRedirectURI)
	pushed2.AcrValues = new(string)
	*pushed2.AcrValues = "urn:solid:loa:2fa:hard"

	pres2, err := h.authz.Register(t.Context(), &flowv1.RegistrationRequest{
		Issuer:  h.issuer,
		Client:  client,
		Request: pushed2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, pres2.RequestUri)

	res2, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: &flowv1.AuthorizationRequest{
			RequestUri: &pres2.RequestUri,
		},
		AuthEvent: stepUpEvent(stepUpACR, authTime),
	})
	require.Error(t, err)
	require.NotNil(t, res2.Error)
	require.Equal(t, "unmet_authentication_requirements", res2.Error.Error)
	require.Empty(t, res2.Code)
}

// rsStepUpGate re-expresses the resource server side of the challenge
// protocol as test-local code (examples/resourceserver/middleware.go is
// package main): freshness and ACR-membership checks over the
// introspection-derived token metadata, emitting a RFC 9470 section 3
// WWW-Authenticate challenge on refusal.
func rsStepUpGate(meta *tokenv1.TokenMeta, acrValues []string, maxAuthAge uint64, now uint64) (challenge string, ok bool) {
	// Freshness check.
	fresh := true
	if maxAuthAge > 0 {
		authTime := meta.GetAuthTime()
		if authTime == 0 || now > authTime+maxAuthAge {
			fresh = false
		}
	}
	// ACR membership check.
	acrOK := true
	if len(acrValues) > 0 {
		acr := meta.GetAcr()
		matched := false
		for _, v := range acrValues {
			if acr == v {
				matched = true
				break
			}
		}
		if !matched {
			acrOK = false
		}
	}
	if fresh && acrOK {
		return "", true
	}

	// RFC 9470 section 3: the challenge carries the max_age and/or
	// acr_values auth-params for the unsatisfied requirements.
	var b strings.Builder
	b.WriteString(`Bearer error="insufficient_user_authentication"`)
	if !fresh {
		b.WriteString(fmt.Sprintf(`, max_age=%d`, maxAuthAge))
	}
	if !acrOK {
		b.WriteString(`, acr_values="` + strings.Join(acrValues, " ") + `"`)
	}
	return b.String(), false
}

// parseChallengeParams extracts the auth-params of a WWW-Authenticate
// challenge header (RFC 9470 section 3: clients parse max_age / acr_values
// out of the challenge to build the follow-up authorization request).
func parseChallengeParams(challenge string) (acrValues string, maxAge uint64) {
	maxAge = 0
	for _, part := range strings.Split(challenge, ",") {
		part = strings.TrimSpace(part)
		if v, found := strings.CutPrefix(part, "max_age="); found {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				maxAge = n
			}
		}
		if v, found := strings.CutPrefix(part, "acr_values="); found {
			acrValues = strings.Trim(v, `"`)
		}
	}
	return acrValues, maxAge
}

// TestRFC9470_RSChallengeRoundTrip proves the full protocol loop at the
// HTTP-relevant level: a stale/insufficient token makes the RS gate emit
// an insufficient_user_authentication challenge, the client parses
// max_age/acr_values out of it, re-authorizes with a fresh matching login
// event, and the new token satisfies the gate (RFC 9470 sections 3-6).
func TestRFC9470_RSChallengeRoundTrip(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	now := uint64(time.Now().Unix())

	t.Run("stale token triggers max_age challenge", func(t *testing.T) {
		// Mint a token whose login is an hour old.
		verifier, _ := newPKCEPair(t)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.AcrValues = new(string)
		*req.AcrValues = stepUpACR

		stale := uint64(time.Now().Add(-1 * time.Hour).Unix())
		code := h.seedAuthorizationWithEvent(t, client, req, stepUpEvent(stepUpACR, stale))
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.NoError(t, err)

		// RS gate with maxAuthAge=30 introspects the token (metadata read
		// via introspection, mirroring the example RS).
		ires, err := h.introspect(t, client.ClientId, res.AccessToken.Value)
		require.NoError(t, err)
		require.NotNil(t, ires.Token.Metadata)

		challenge, ok := rsStepUpGate(ires.Token.Metadata, nil, 30, now)
		require.False(t, ok)
		require.Contains(t, challenge, `error="insufficient_user_authentication"`)
		require.Contains(t, challenge, `max_age=30`)
	})

	t.Run("insufficient acr triggers acr_values challenge", func(t *testing.T) {
		verifier, _ := newPKCEPair(t)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.AcrValues = new(string)
		*req.AcrValues = "urn:solid:loa:2fa:hard" // the login can achieve it

		code := h.seedAuthorizationWithEvent(t, client, req, stepUpEvent("urn:solid:loa:2fa:hard", now))
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.NoError(t, err)

		ires, err := h.introspect(t, client.ClientId, res.AccessToken.Value)
		require.NoError(t, err)
		require.NotNil(t, ires.Token.Metadata)

		// The RS only accepts the 1fa ACR.
		challenge, ok := rsStepUpGate(ires.Token.Metadata, []string{stepUpACR}, 0, now)
		require.False(t, ok)
		require.Contains(t, challenge, `error="insufficient_user_authentication"`)
		require.Contains(t, challenge, `acr_values="`+stepUpACR+`"`)
	})

	t.Run("challenge drives a satisfying re-authorization", func(t *testing.T) {
		// Seed a token that violates BOTH gate requirements: stale login
		// and an ACR below the resource's requirement.
		verifier, _ := newPKCEPair(t)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.AcrValues = new(string)
		*req.AcrValues = "urn:solid:loa:2fa:hard" // the login can achieve it

		stale := uint64(time.Now().Add(-1 * time.Hour).Unix())
		code := h.seedAuthorizationWithEvent(t, client, req, stepUpEvent("urn:solid:loa:2fa:hard", stale))
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.NoError(t, err)

		ires, err := h.introspect(t, client.ClientId, res.AccessToken.Value)
		require.NoError(t, err)
		challenge, ok := rsStepUpGate(ires.Token.Metadata, []string{stepUpACR}, 30, now)
		require.False(t, ok)
		require.Contains(t, challenge, `max_age=30`)
		require.Contains(t, challenge, `acr_values="`+stepUpACR+`"`)

		// Client parses the challenge into the follow-up request params
		// (RFC 9470 section 4).
		acrValues, maxAge := parseChallengeParams(challenge)
		require.Equal(t, stepUpACR, acrValues)
		require.Equal(t, uint64(30), maxAge)

		// Re-authorize with the extracted parameters and a fresh matching event.
		verifier2, _ := newPKCEPair(t)
		req2 := validAuthorizationRequest(client.ClientId, verifier2, testRedirectURI)
		req2.AcrValues = &acrValues
		req2.MaxAge = &maxAge

		freshEvent := uint64(time.Now().Unix())
		code2 := h.seedAuthorizationWithEvent(t, client, req2, stepUpEvent(stepUpACR, freshEvent))
		res2, err := h.redeemCode(t, client.ClientId, code2, verifier2, testRedirectURI)
		require.NoError(t, err)

		ires2, err := h.introspect(t, client.ClientId, res2.AccessToken.Value)
		require.NoError(t, err)
		require.NotNil(t, ires2.Token.Metadata)

		// The gate passes (200-path).
		challenge2, ok2 := rsStepUpGate(ires2.Token.Metadata, []string{stepUpACR}, 30, uint64(time.Now().Unix()))
		require.True(t, ok2, "gate must pass after step-up, got challenge %q", challenge2)
		require.Empty(t, challenge2)
	})
}

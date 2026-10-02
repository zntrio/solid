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

// CIBA poll-mode client demo (OpenID Client-Initiated Backchannel
// Authentication Core 1.0).
//
// Prerequisite: the example authorization server is running
// (go run ./examples/authorizationserver).
//
// The demo drives the full CIBA round trip:
//
//  1. authenticate the fixture client with a private_key_jwt ES256 assertion;
//  2. POST a signed request object (CIBA section 7.1.1) to /bc-authorize,
//     declaring the DPoP key thumbprint as dpop_jkt (RFC 9449 section 10);
//  3. approve the request on the authentication device (the /backchannel
//     endpoint, basic-auth subject "hello" — standing in for the end user
//     confirming the binding_message on their phone);
//  4. poll the token endpoint with grant urn:openid:params:grant-type:ciba,
//     honoring the advertised interval and slow_down, presenting a DPoP
//     proof of the bound key with every poll;
//  5. print the minted access token (never a refresh token — the CIBA grant
//     strips offline access, RFC 9700 section 4.12.2).
package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/jwsreq"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/token/jwt"
)

// issuer is the AS issuer identifier, overridable with SOLID_EXAMPLE_ISSUER.
var issuer = envOr("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")

const (
	clientID     = "ciba-fixture-client"
	clientJWK    = `{"kty":"EC","d":"olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use":"sig","crv":"P-256","x":"h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y":"yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg":"ES256"}`
	bindingMsg   = "W4SCT"
	pollAttempts = 10
	// es256 is the fixture key's signature algorithm (elliptic curve only,
	// repo rule).
	es256 = "ES256"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ciba demo failed:", err)
		os.Exit(1)
	}
}

//nolint:gocyclo,funlen // linear demo flow; each step is a protocol phase
func run() error {
	ctx := context.Background()

	// Build the OIDC client: resolves discovery metadata (the CIBA endpoints
	// are advertised there) and mints private_key_jwt assertions with the
	// ES256 fixture key.
	oidcClient, err := client.HTTP(ctx, issuer, &client.Options{
		ClientID: clientID,
		JWK:      []byte(clientJWK),
		Scopes:   []string{"openid", "profile"},
	})
	if err != nil {
		return fmt.Errorf("unable to initialize client: %w", err)
	}
	md := oidcClient.ServerMetadata()
	if md.BackchannelAuthenticationEndpoint == "" {
		return fmt.Errorf("server metadata does not advertise a backchannel authentication endpoint")
	}
	fmt.Println("→ backchannel authentication endpoint:", md.BackchannelAuthenticationEndpoint)

	// DPoP prover over the fixture ES256 key (RFC 9449): the same key's
	prover := dpop.DefaultProver(jwt.DPoPSigner(es256, func(context.Context) (jwk.Key, error) {
		keySet, parseErr := jwk.Parse([]byte(clientJWK))
		if parseErr != nil {
			return nil, parseErr
		}
		key, _ := keySet.Key(0)
		// DPoP proofs embed the JWK: it must be identifiable (kid).
		if setErr := key.Set(jwk.KeyIDKey, clientID); setErr != nil {
			return nil, setErr
		}
		return key, nil
	}))
	jkt, err := keyThumbprint()
	if err != nil {
		return fmt.Errorf("unable to compute DPoP key thumbprint: %w", err)
	}
	fmt.Println("→ DPoP key thumbprint (dpop_jkt):", jkt)

	// 1. Signed request object (CIBA section 7.1.1): all authentication
	// request parameters ride the JWT; none may appear outside it.
	requestObject, err := signedRequest(issuer, jkt)
	if err != nil {
		return fmt.Errorf("unable to sign request object: %w", err)
	}

	// 2. bc-authorize. A fresh client assertion per request: the AS burns
	// each jti on use (RFC 7523 anti-replay), so the bc-authorize and token
	// endpoint calls must not share one assertion.
	authAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	authRes, err := backchannelAuthorize(ctx, md, authAssertion, requestObject)
	if err != nil {
		return err
	}
	fmt.Printf("← auth_req_id: %s (expires_in: %ds, interval: %ds)\n", authRes.AuthReqId, authRes.ExpiresIn, authRes.Interval)
	fmt.Println("→ approving on the authentication device (binding_message:", bindingMsg+`)`)

	// 3. Approve on the authentication device. In a real deployment the
	// end user confirms the binding_message on their phone; the example
	// AS exposes the approval channel at /backchannel behind basic auth
	// (the subject resolves the login_hint "hello").
	if err := approve(ctx, authRes.AuthReqId); err != nil {
		return fmt.Errorf("unable to approve on the authentication device: %w", err)
	}

	// 4. Poll the token endpoint, honoring the advertised interval and
	// slow_down (CIBA section 11).
	interval := authRes.Interval
	if interval == 0 {
		interval = 5
	}
	for range pollAttempts {
		time.Sleep(time.Duration(interval) * time.Second)

		// Fresh assertion per poll: each jti is single-use (RFC 7523).
		pollAssertion, err := oidcClient.Assertion()
		if err != nil {
			return fmt.Errorf("unable to mint client assertion: %w", err)
		}
		// Fresh DPoP proof for the token-endpoint request (the AS verifies
		// it and records the thumbprint as the token confirmation).
		proof, err := prover.Prove(http.MethodPost, md.TokenEndpoint)
		if err != nil {
			return fmt.Errorf("unable to mint DPoP proof: %w", err)
		}
		res, err2 := pollToken(ctx, md, pollAssertion, proof, authRes.AuthReqId)
		if err2 != nil {
			return err2
		}
		switch res.Error {
		case "":
			// 5. Token minted: access token only, never a refresh token.
			fmt.Println("← access_token:", res.AccessToken)
			fmt.Println("← token_type:  ", res.TokenType)
			fmt.Println("← no refresh token, as designed (RFC 9700 §4.12.2)")
			return nil
		case "slow_down":
			// CIBA section 11: the interval increases by 5 seconds.
			interval += 5
			fmt.Println("← slow_down; new interval:", interval)
		case "authorization_pending":
			fmt.Println("← authorization_pending; polling again")
		default:
			return fmt.Errorf("token endpoint error: %s", res.Error)
		}
	}
	return fmt.Errorf("authorization did not complete within %d polls", pollAttempts)
}

// backchannelAuthenticationResponse carries the bc-authorize response
// (CIBA section 7.3).
type backchannelAuthenticationResponse struct {
	AuthReqId string `json:"auth_req_id"`
	ExpiresIn uint64 `json:"expires_in"`
	Interval  uint64 `json:"interval"`
	Error     string `json:"error,omitempty"`
}

// backchannelAuthorize POSTs the signed request object to the backchannel
// authentication endpoint with the client assertion.
func backchannelAuthorize(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, requestObject string) (*backchannelAuthenticationResponse, error) {
	params := url.Values{}
	params.Add("request", requestObject)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.BackchannelAuthenticationEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to reach the backchannel authentication endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var res backchannelAuthenticationResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("unable to decode bc-authorize response: %w", err)
	}
	if res.Error != "" || res.AuthReqId == "" {
		return nil, fmt.Errorf("bc-authorize rejected the request: %s", res.Error)
	}
	return &res, nil
}

// approve completes the end-user approval on the authentication device
// (CIBA section 8): the example AS's /backchannel endpoint, behind the
// hello/world basic-auth fixture standing in for the user's phone.
func approve(ctx context.Context, authReqID string) error {
	params := url.Values{}
	params.Add("auth_req_id", authReqID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/backchannel", strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("hello", "world")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to reach the authentication device endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("approval failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// tokenPollResponse carries the token-endpoint response of a CIBA poll
// (CIBA section 10.1 / 11).
type tokenPollResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// pollToken polls the token endpoint with the CIBA grant, presenting the
// DPoP proof bound to the session's dpop_jkt.
func pollToken(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, proof, authReqID string) (*tokenPollResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeCIBA)
	params.Add("auth_req_id", authReqID)
	params.Add("client_id", clientID)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to reach the token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var res tokenPollResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}
	return &res, nil
}

// signedRequest builds the ES256-signed authentication request object
// (CIBA section 7.1.1): iss = client_id, aud = issuer, exp/iat/nbf/jti
// mandatory, the authentication request parameters as claims, and the
// DPoP key thumbprint as dpop_jkt (RFC 9449 section 10 binding). The
// CIBA-specific binding_message claim has no proto representation and is
// injected through the encoder envelope.
func signedRequest(expectedIssuer, jkt string) (string, error) {
	keySet, err := jwk.Parse([]byte(clientJWK))
	if err != nil {
		return "", fmt.Errorf("unable to decode fixture key: %w", err)
	}
	privateKey, ok := keySet.Key(0)
	if !ok {
		return "", fmt.Errorf("fixture JWK has no key")
	}
	// The JWT signer requires an identifiable key (kid).
	if kid, ok := privateKey.KeyID(); !ok || kid == "" {
		if err := jwk.AssignKeyID(privateKey); err != nil {
			return "", fmt.Errorf("unable to assign fixture key id: %w", err)
		}
	}
	keyProvider := jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return privateKey, nil
	})

	now := time.Now()
	envelope := map[string]any{
		"iss":             clientID,
		"aud":             expectedIssuer,
		"exp":             now.Add(5 * time.Minute).Unix(),
		"iat":             now.Unix(),
		"nbf":             now.Unix(),
		"jti":             random.String(16),
		"binding_message": bindingMsg,
	}

	encoder := jwsreq.AuthorizationRequestEncoderWithOptions(
		jwt.RequestSigner(es256, keyProvider),
		envelope,
	)
	return encoder.Encode(context.Background(), &flowv1.AuthorizationRequest{
		Scope:     "openid profile",
		LoginHint: new("hello"),
		DpopJkt:   new(jkt),
		// RFC 8707: the target resource identifier becomes the audience of
		// the minted access token; the demo targets the example resource
		// server.
		Audience: "http://localhost:8085",
	})
}

// keyThumbprint computes the RFC 7638 thumbprint of the fixture DPoP key,
// base64url-encoded — the dpop_jkt value the authorization server binds
// the session to (RFC 9449 section 10).
func keyThumbprint() (string, error) {
	keySet, err := jwk.Parse([]byte(clientJWK))
	if err != nil {
		return "", fmt.Errorf("unable to decode fixture key: %w", err)
	}
	key, ok := keySet.Key(0)
	if !ok {
		return "", fmt.Errorf("fixture JWK has no key")
	}
	raw, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("unable to compute thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// envOr reads an environment variable, falling back to def when unset or
// empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

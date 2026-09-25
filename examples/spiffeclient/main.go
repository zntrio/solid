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

// spiffeclient demonstrates OAuth SPIFFE client authentication
// (draft-ietf-oauth-spiffe-client-auth-02) with a JWT-SVID: it derives the
// example.org trust-domain signing key shared with the example authorization
// server bundle, mints a short-lived JWT-SVID for the registered workload
// spiffe://example.org/my-oauth-client, and exchanges it for an access token
// at the token endpoint using the jwt-spiffe client assertion type.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/spiffedemo"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
)

const (
	tokenEndpoint   = "http://127.0.0.1:8080/token"
	bodyLimiterSize = 5 << 20 // 5 Mb
)

// -----------------------------------------------------------------------------

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	fmt.Println(">> OAuth SPIFFE client authentication demo (JWT-SVID)")

	// The demo signs the JWT-SVID with the fixed trust-domain key whose
	// public part is served by the example AS bundle (spiffedemo fixtures).
	signingKey := spiffedemo.JWTSVIDSigningKey()
	var rawKey any
	if err := jwxjwk.Export(signingKey, &rawKey); err != nil {
		return fmt.Errorf("unable to materialize signing key: %w", err)
	}

	// Build the JWT-SVID (draft section 3.1): sub is the client SPIFFE ID,
	// aud is the AS token endpoint as sole value, short lifetime, random jti.
	now := time.Now()
	svid := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": spiffedemo.ClientSPIFFEID,
		"sub": spiffedemo.ClientSPIFFEID,
		"aud": tokenEndpoint,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": random.String(16),
	})
	svidRaw, err := svid.SignedString(rawKey)
	if err != nil {
		return fmt.Errorf("unable to sign jwt-svid: %w", err)
	}
	fmt.Printf("JWT-SVID: %s\n", svidRaw)

	// Prepare the token request (RFC 6749 section 4.4 client_credentials
	// with the jwt-spiffe client assertion, draft section 3.1).
	form := url.Values{}
	form.Set("grant_type", oidc.GrantTypeClientCredentials)
	form.Set("client_assertion_type", oidc.AssertionTypeJWTSPIFFE)
	form.Set("client_assertion", svidRaw)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("unable to prepare token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to process the request: %w", err)
	}
	defer resp.Body.Close()

	// Decode the token response
	var tokenResponse client.Token
	if err := json.NewDecoder(io.LimitReader(resp.Body, bodyLimiterSize)).Decode(&tokenResponse); err != nil {
		return fmt.Errorf("unable to decode json response: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return fmt.Errorf("no access token in response")
	}

	fmt.Printf("Access Token: %s\n", tokenResponse.AccessToken)

	return nil
}

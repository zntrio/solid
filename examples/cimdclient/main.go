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

// cimdclient demonstrates OAuth client authentication with a Client ID
// Metadata Document client (draft-ietf-oauth-client-id-metadata-document):
// the client identifies itself with the URL-shaped identifier
// https://cimd.example.org/client, which the example authorization server
// resolves to the cimddemo fixture document at authentication time. The
// document declares the private_key_jwt method with an ML-DSA-65 key, so the
// client builds a JWT assertion signed with the fixture seed and exchanges it
// for a DPoP-bound access token at the token endpoint (the example AS policy
// applies dpop_bound_access_tokens to resolved documents, so the request also
// carries a DPoP proof of the same key, RFC 9449 section 5), then presents
// the token to the example resource server, which introspects it under the
// authorized_introspection_clients grant declared in the document.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/cimddemo"
	exampleenv "zntr.io/solid/examples/internal/exampleenv"
	"zntr.io/solid/examples/internal/flowlog"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token/jwt"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	ctx := context.Background()

	// AS issuer identifier, overridable with SOLID_EXAMPLE_ISSUER.
	issuer := exampleenv.Or("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")

	// Rebuild the client JWK (AKP, ML-DSA-65) from the published fixture
	// seed: the private seed drives the JWT assertion signature, the
	// derived public key matches the JWKS published in the document.
	seed, err := base64.RawURLEncoding.DecodeString(cimddemo.ClientSeedB64)
	if err != nil {
		return fmt.Errorf("unable to decode client seed: %w", err)
	}
	jwkDoc := fmt.Sprintf(`{"alg":"ML-DSA-65","d":%q,"kid":%q,"kty":"AKP","pub":%q}`, base64.RawURLEncoding.EncodeToString(seed), cimddemo.ClientIdentifierURL, cimddemo.ClientPubB64)

	// Create the OIDC client instance for the CIMD identifier.
	oidcClient, err := client.HTTP(ctx, issuer, &client.Options{
		ClientID: cimddemo.ClientIdentifierURL,
		JWK:      []byte(jwkDoc),

		// Request an access token for the introspection demo: the resource
		// indicator is the token audience (RFC 8707), the scope the
		// permission carried by the token.
		Resource: "http://127.0.0.1:8085",
		Scope:    "timestamp:read",

		// Print the protocol flow (metadata, token, introspection).
		HTTPClient: flowlog.New(),
	})
	if err != nil {
		return fmt.Errorf("unable to create oidc client: %w", err)
	}

	// The DPoP prover of the client key (AKP, ML-DSA-65): proofs for the
	// token endpoint and any DPoP-bound resource access.
	prover := dpopProver(jwkDoc)

	// Build the private_key_jwt client assertion. The authorization server
	// resolves the identifier through its Client ID Metadata Document
	// (cimd.Resolver) and verifies the assertion with the JWKS the document
	// publishes.
	assertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to build client assertion: %w", err)
	}
	// The example AS policy resolves CIMD documents with
	// dpop_bound_access_tokens=true (authorizationserver main.go): the
	// minted token is sender-constrained, so the token request MUST carry
	// a DPoP proof of the client's key (RFC 9449 section 5). The proof is
	// minted with the same ML-DSA key that signs the assertion; the
	// derived token carries cnf.jkt and token_type=DPoP.
	proof, err := prover.Prove(http.MethodPost, issuer+"/token")
	if err != nil {
		return fmt.Errorf("unable to mint dpop proof: %w", err)
	}
	token, err := fetchAccessToken(ctx, issuer, assertion, proof)
	if err != nil {
		return fmt.Errorf("unable to retrieve access token: %w", err)
	}
	fmt.Printf("Access Token: %s (token_type=%s)\n", token.AccessToken, token.TokenType)

	// Let the token become usable (nbf is iat+1 at the authorization
	// server) and the storage indexes settle.
	time.Sleep(2 * time.Second)

	// Introspect the token with a fresh assertion (client assertions are
	// single-use: the jti is burned at each request).
	introspectionAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to build introspection assertion: %w", err)
	}
	it, err := oidcClient.Introspect(ctx, introspectionAssertion, token.AccessToken)
	if err != nil {
		return fmt.Errorf("unable to introspect token: %w", err)
	}
	fmt.Printf("Introspection: client_id=%s status=%s\n", it.Metadata.GetClientId(), it.Status)

	return nil
}

// dpopProver prepares the DPoP prover backed by the client ML-DSA key
// (the same fixture key that signs the private_key_jwt assertion).
func dpopProver(jwkDoc string) dpop.Prover {
	keySet, err := jwk.Parse([]byte(jwkDoc))
	if err != nil {
		panic(err)
	}
	key, _ := keySet.Key(0)
	return dpop.DefaultProver(jwt.DPoPSigner("ML-DSA-65", func(context.Context) (jwk.Key, error) {
		return key, nil
	}))
}

// fetchAccessToken drives the token endpoint with the client assertion and
// the DPoP proof, and decodes the issued access token.
func fetchAccessToken(ctx context.Context, issuer, assertion, proof string) (*client.Token, error) {
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("resource", "http://127.0.0.1:8085") // RFC 8707 resource indicator: the timestamp service
	params.Add("scope", "timestamp:read")
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("client_assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/token", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := flowlog.New().Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to request token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("token request failed with %s: %s", resp.Status, body)
	}
	var token client.Token
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}
	return &token, nil
}

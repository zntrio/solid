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
// for an access token at the token endpoint, then presents the token to the
// example resource server, which introspects it under the
// authorized_introspection_clients grant declared in the document.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/cimddemo"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	ctx := context.Background()

	// Rebuild the client JWK (AKP, ML-DSA-65) from the published fixture
	// seed: the private seed drives the JWT assertion signature, the
	// derived public key matches the JWKS published in the document.
	seed, err := base64.RawURLEncoding.DecodeString(cimddemo.ClientSeedB64)
	if err != nil {
		return fmt.Errorf("unable to decode client seed: %w", err)
	}
	jwkDoc := fmt.Sprintf(`{"alg":"ML-DSA-65","d":%q,"kid":%q,"kty":"AKP","pub":%q}`, base64.RawURLEncoding.EncodeToString(seed), cimddemo.ClientIdentifierURL, cimddemo.ClientPubB64)

	// Create the OIDC client instance for the CIMD identifier.
	oidcClient, err := client.HTTP(ctx, "http://127.0.0.1:8080", &client.Options{
		ClientID: cimddemo.ClientIdentifierURL,
		JWK:      []byte(jwkDoc),
		Scopes:   []string{"openid"},
		Audience: "http://localhost:8085",
	})
	if err != nil {
		return fmt.Errorf("unable to create oidc client: %w", err)
	}

	// Build the private_key_jwt client assertion. The authorization server
	// resolves the identifier through its Client ID Metadata Document
	// (cimd.Resolver) and verifies the assertion with the JWKS the document
	// publishes.
	assertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to build client assertion: %w", err)
	}

	// Exchange the assertion for an access token (client_credentials).
	token, err := oidcClient.ClientCredentials(ctx, assertion)
	if err != nil {
		return fmt.Errorf("unable to retrieve access token: %w", err)
	}
	fmt.Printf("Access Token: %s\n", token.AccessToken)

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

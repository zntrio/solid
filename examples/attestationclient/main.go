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

package main

import (
	"bytes"
	"context"
	"crypto/mldsa"
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

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	random "zntr.io/solid/sdk/random"
)

const bodyLimiterSize = 5 << 20 // 5 Mb

// -----------------------------------------------------------------------------

func getAttestation(ctx context.Context, pub *mldsa.PublicKey) (string, error) {
	// Pack the public key as JWK
	pubJWK, err := jwk.NewMLDSAKeyFromPublic(pub)
	if err != nil {
		return "", fmt.Errorf("unable to import client public key: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return "", fmt.Errorf("unable to set key usage: %w", err)
	}
	requestBodyRaw := map[string]any{
		"clientPublicKey": pubJWK,
		"clientId":        "attestation-client",
	}

	payload, err := json.Marshal(requestBodyRaw)
	if err != nil {
		return "", fmt.Errorf("unable to prepare attestation request payload: %w", err)
	}

	// Compute attestation
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:8087/attestations/sign", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("unable to prepare attestation backend client request: %w", err)
	}

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to process the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid attestation endpoint status code, got %d", resp.StatusCode)
	}

	attestation, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("unable to read attestation content: %w", err)
	}

	return string(attestation), nil
}

func computeClientPOP(priv *mldsa.PrivateKey) (string, error) {
	// Derive the public JWK to embed in the proof header
	key, err := jwk.NewMLDSAKey(priv)
	if err != nil {
		return "", fmt.Errorf("unable to import client key: %w", err)
	}
	pubJWK, err := key.PublicKey()
	if err != nil {
		return "", fmt.Errorf("unable to derive client public key: %w", err)
	}

	now := time.Now().Unix()

	// Build and sign the PoP
	tok := gojwt.NewWithClaims(jwk.SigningMethodMLDSA65, gojwt.MapClaims{
		"iss": "attestation-client",
		"aud": "http://127.0.0.1:8080",
		"iat": now,
		"nbf": now - 1,
		"exp": now + 30, // Valid for 30s
		"jti": random.String(8),
	})
	tok.Header["typ"] = "client-attestation-pop+jwt"
	tok.Header["jwk"] = pubJWK
	raw, err := tok.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("unable to sign client attestation PoP: %w", err)
	}

	return raw, nil
}

func getToken(ctx context.Context, assertion string) (*client.Token, error) {
	// Prepare parameters
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("client_id", "attestation-client")
	params.Add("client_assertion", assertion)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTClientAttestation)

	// Query token endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:8080/token", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare token request: %w", err)
	}

	// Set approppriate header value
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Do the query
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		var err corev1.Error

		// Decode json error
		if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&err); err != nil {
			return nil, fmt.Errorf("unable to decode json error for token retrieval request: %w", err)
		}

		return nil, fmt.Errorf("unable to request for token got %s, %s", err.Err, err.ErrorDescription)
	}

	// Decode payload
	var token client.Token
	if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&token); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}

	return &token, nil
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	// Generate client instance key (post-quantum ML-DSA-65)
	pk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return fmt.Errorf("unable to generate client instance keypair: %w", err)
	}

	attestation, err := getAttestation(ctx, pk.PublicKey())
	if err != nil {
		return fmt.Errorf("unable to retrieve remote attestation: %w", err)
	}

	fmt.Printf("Client Attestation: %s\n", attestation)

	pop, err := computeClientPOP(pk)
	if err != nil {
		return fmt.Errorf("unable to compute client attestation PoP: %w", err)
	}

	fmt.Printf("Client Attestation PoP: %s\n", pop)

	t, err := getToken(ctx, attestation+"~"+pop)
	if err != nil {
		return fmt.Errorf("unable to retrieve OAuth2 token: %w", err)
	}

	fmt.Printf("Access Token: %s\n", t.AccessToken)

	// Let some time to persistence to sync.
	time.Sleep(1000 * time.Millisecond)

	// Call the timestamp service
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:8085", nil)
	if err != nil {
		panic(err)
	}

	// Set the access token value.
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))

	// Use OAuth2 client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	timestampRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(timestampRaw))

	return nil
}

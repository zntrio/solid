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
	"context"
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/cimddemo"
	exampleenv "zntr.io/solid/examples/internal/exampleenv"
	"zntr.io/solid/sdk/types"
)

func ResourceMetadata() http.Handler {
	// Prepare metadata
	md := &discoveryv1.ProtectedResourceMetadata{
		Resource: "http://127.0.0.1:8085",
		ScopesSupported: []string{
			"timestamp:read",
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(md); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func ResourceHandler(issuer string, pub ed25519.PublicKey, priv ed25519.PrivateKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create the timestamp
		now := time.Now().UTC().UnixNano()

		// Create a random nonce
		var nonce [8]byte
		if _, err := io.ReadFull(cryptoRand.Reader, nonce[:]); err != nil {
			http.Error(w, "Unable to generate nonce for signature", http.StatusInternalServerError)
			return
		}

		// Encode timestamp as a byte array
		tsRaw := make([]byte, 8)
		binary.BigEndian.PutUint64(tsRaw, uint64(now))

		// Prepare protected payload
		protected := []byte("signed-timestamp-protocol-v1")
		protected = append(protected, issuer...)
		protected = append(protected, nonce[:]...)
		protected = append(protected, tsRaw...)

		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(map[string]any{
			"@context":  "https://zntr.io/schemas/security/v1",
			"@type":     "SignedTimestamp",
			"issuer":    issuer,
			"timestamp": now,
			"signature": map[string]any{
				"scheme": "ed25519",
				"nonce":  base64.RawURLEncoding.EncodeToString(nonce[:]),
				"proof":  base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, protected)),
				"pub":    base64.RawURLEncoding.EncodeToString(pub),
			},
		}); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	ctx := context.Background()
	issuer := "http://localhost:8085" // this RS's own issuer
	asIssuer := exampleenv.Or("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")

	// Rebuild the resource server JWK (AKP, ML-DSA-65) from the published
	// fixture seed (agentclient precedent): the same key drives the
	// private_key_jwt client assertions at introspection.
	seed, err := base64.RawURLEncoding.DecodeString(cimddemo.ResourceServerClientSeedB64)
	if err != nil {
		panic(fmt.Errorf("unable to decode resource server seed: %w", err))
	}
	jwkDoc := fmt.Sprintf(`{"alg":"ML-DSA-65","d":%q,"kid":%q,"kty":"AKP","pub":%q}`,
		base64.RawURLEncoding.EncodeToString(seed), cimddemo.ResourceServerClientIdentifierURL, cimddemo.ResourceServerClientPubB64)

	// Create the OIDC client for the CIMD identifier: the RS is an
	// introspection-only client, authorized on the token owners'
	// documents (authorized_introspection_clients).
	oidcClient, err := client.HTTP(ctx, asIssuer, &client.Options{
		ClientID: cimddemo.ResourceServerClientIdentifierURL,
		JWK:      []byte(jwkDoc),
	})
	if err != nil {
		panic(err)
	}

	// Create the signing key from a cryptographically secure source; a
	// deterministic seed would let anyone reproduce this resource server's
	// key material.
	pub, priv, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		panic(err)
	}

	// Create router: two surfaces over the same PoP/audience/scope
	// enforcement.
	//
	// `/` is the strict RFC 9470 step-up surface: end-user tokens only —
	// an ACR from urn:solid:loa:1fa:any and max_age 30 s are required, so
	// client-credentials tokens (no end-user login event) fail closed.
	//
	// `/machine` is the client surface: same audience/scope/PoP checks, no
	// end-user ACR requirement — the machine credential is the client
	// itself (client_credentials, RFC 6749 §4.4). The deviceclient and
	// attestationclient demos target this surface.
	http.Handle("/", Authorizer(ResourceHandler(issuer, pub, priv), "timestamp:read", oidcClient, types.StringArray{"urn:solid:loa:1fa:any"}, 30))
	http.Handle("/machine", Authorizer(ResourceHandler(issuer, pub, priv), "timestamp:read", oidcClient, nil, 0))
	http.Handle("/.well-known/oauth-protected-resource", ResourceMetadata())

	server := &http.Server{
		// Loopback by default: the example serves plaintext HTTP — binding
		// all interfaces would expose tokens and Basic credentials to the
		// network. Override with SOLID_EXAMPLE_LISTEN_ADDR for containerized
		// demos.
		Addr:              exampleenv.Or("SOLID_EXAMPLE_LISTEN_ADDR", "127.0.0.1:8085"),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

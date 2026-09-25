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
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"time"

	"zntr.io/solid/examples/authorizationserver/cimddemo"
	"zntr.io/solid/examples/authorizationserver/handlers"
	"zntr.io/solid/examples/authorizationserver/middleware"
	"zntr.io/solid/examples/authorizationserver/spiffedemo"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/cimd"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/pairwise"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/device"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

func main() {
	// Generators
	authorizationCodes := generator.DefaultAuthorizationCode()
	requestURIs := generator.DefaultRequestURI()
	deviceCodes := generator.DefaultDeviceCode()
	deviceUserCodes := generator.DefaultDeviceUserCode()

	// Storage key for keyed hashing of in-memory indexes. Generated at boot:
	// the example server does not persist storage across restarts.
	storageKey := make([]byte, 32)
	if _, err := rand.Read(storageKey); err != nil {
		panic(fmt.Errorf("unable to generate storage key: %w", err))
	}

	// Create storage
	resources := inmemory.Resources()
	tokens := inmemory.Tokens(storageKey)
	// Wrap in-memory client storage with CIMD resolution: pre-registered
	// clients win, URL-shaped https:// client identifiers without a stored
	// registration are resolved from their Client ID Metadata Document.
	// The AS is only authorized to pull documents for the explicitly
	// allow-listed identifiers below: CIMD resolution is a server-side
	// fetch triggered by a client-supplied identifier, so the host
	// surface is pinned by the operator, never by the caller. The demo
	// document fixture (examples/authorizationserver/cimddemo) is served
	// by an in-memory fetcher; remote documents would go through the
	// hardened httpfetch (SSRF pre-flight, https-only), itself still
	// behind the allow-list.
	cimdResolver := cimd.NewAllowlistFilter(
		cimd.NewResolver(cimddemo.StaticFetcher()),
		// Operator-pinned identifiers and hosts authorized for CIMD
		// resolution. Prefix entries (trailing slash) grant a whole
		// remote host.
		cimddemo.ClientIdentifierURL,
	)
	clients := inmemory.NewClientReader(inmemory.Clients(), cimdResolver)
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests(storageKey)
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)

	// Token generator
	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("very-secret-key-for-access-token-verification"))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("very-secret-key-for-refresh-token-verification"))

	// Prepare services
	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	tokenz := token.New(accessTokens, refreshTokens, clients, authRequests, authSessions, deviceSessions, tokens, resources)
	devicez := device.New(clients, deviceSessions, deviceCodes, deviceUserCodes, inmemory.UserCodeAttempts())
	issuer := "http://127.0.0.1:8080"

	// SPIFFE trust bundles (draft-ietf-oauth-spiffe-client-auth-02 section 6):
	// the example.org trust domain keys are pre-configured statically; the
	// bundle is also served at /spiffe/bundle.json so a bundle-endpoint
	// consumer can fetch it (the demo assembly itself uses the static source,
	// httpfetch refuses loopback fetches by SSRF hardening).
	spiffeBundleSet := jwk.NewSet()
	_ = spiffeBundleSet.Set("keys", []jwk.Key{func() jwk.Key {
		k := spiffedemo.JWTSVIDPublicKey()
		_ = k.Set(jwk.KeyUsageKey, spiffe.KeyUseJWTSVID)
		return k
	}()})
	spiffeBundles := spiffe.NewStaticBundleSource(map[string]jwk.Set{
		spiffedemo.TrustDomain: spiffeBundleSet,
	})

	// Middlewares
	secHeaders := middleware.SecurityHaders()
	basicAuth := middleware.BasicAuthentication()
	clientAuth := middleware.ClientAuthentication(clients, issuer, []string{"ES256", jwk.MLDSA65}, spiffeBundles)

	// Request encoders
	keys := keyProvider()
	keySet := keySetProvider()
	dpopVerifier := dpop.DefaultVerifier(proofs, jwt.DefaultVerifier(keySet, []string{jwk.MLDSA65}))
	jarmEncoder := jarm.Encoder(jwt.JARMSigner(jwk.MLDSA65, keys))
	pairwiseEncoder := pairwise.Hash([]byte("U|(vBPu45_Vkvv*Tr*8Y[^s?,$ka@bQziM5]9.+[{.n47]'zokA7-j8ypJ=W]WS"))

	// Create router
	http.Handle("/.well-known/oauth-authorization-server", handlers.Metadata(issuer, jwt.ServerMetadata(jwk.MLDSA65, keys)))
	http.Handle("/.well-known/openid-configuration", handlers.Metadata(issuer, jwt.ServerMetadata(jwk.MLDSA65, keys)))
	http.Handle("/keys", handlers.JWKS(keySet))
	http.Handle("/spiffe/bundle.json", handlers.SpiffeBundle(spiffeBundleSet))
	http.Handle("/par", middleware.Adapt(handlers.PushedAuthorizationRequest(issuer, authz, dpopVerifier), clientAuth))
	http.Handle("/authorize", middleware.Adapt(handlers.Authorization(issuer, authz, clients, jarmEncoder, pairwiseEncoder), secHeaders, basicAuth))
	http.Handle("/token", middleware.Adapt(handlers.Token(issuer, tokenz, dpopVerifier), clientAuth))
	http.Handle("/token/introspect", middleware.Adapt(handlers.TokenIntrospection(issuer, tokenz), clientAuth))
	http.Handle("/token/revoke", middleware.Adapt(handlers.TokenRevocation(issuer, tokenz), clientAuth))
	http.Handle("/device/authorize", middleware.Adapt(handlers.DeviceAuthorization(issuer, devicez), clientAuth))
	http.Handle("/device", middleware.Adapt(handlers.Device(issuer, devicez), secHeaders, basicAuth))

	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

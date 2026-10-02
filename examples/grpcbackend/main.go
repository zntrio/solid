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

// grpcbackend is a reference assembly of the solid SDK as a standalone
// gRPC authorization backend: a presentation layer (HTTP today, CoAP or
// gRPC-native tomorrow) talks to it through the proto-defined services
// while the protocol core stays presentation-agnostic.
//
// Presentation-layer concerns stay out by design: DPoP htm/htu proof
// verification and mutual-TLS certificate extraction are HTTP-bound and
// live in the presentation layer, which forwards the resolved
// token_confirmation and tls_client_cert through the proto fields.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/examples/authorizationserver/spiffedemo"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/grpckit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/clientregistration"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

// es256Alg is the ECDSA P-256 signature algorithm accepted alongside the
// post-quantum ML-DSA-65 (elliptic curves + PQ only, repo rule).
const es256Alg = "ES256"

// clientAssertionAlgorithms is the elliptic-curve + post-quantum signing
// allowlist for client-assertion verification.
var clientAssertionAlgorithms = []string{es256Alg, jwk.MLDSA65}

// authDetailsType is the RFC 9396 authorization details type the example
// backend registers and validates (payment initiation).
const authDetailsType = "payment_initiation"

func main() {
	// Generators
	authorizationCodes := generator.DefaultAuthorizationCode()
	requestURIs := generator.DefaultRequestURI()

	// Storage key for keyed hashing of in-memory indexes. Generated at
	// boot: the example backend does not persist storage across restarts.
	storageKey := make([]byte, 32)
	if _, err := rand.Read(storageKey); err != nil {
		panic(fmt.Errorf("unable to generate storage key: %w", err))
	}

	// Storage
	clients := inmemory.Clients()
	tokens := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests(storageKey)
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)

	// Token generators: hybrid tokens with distinct random MAC keys for
	// access and refresh tokens.
	atKey := make([]byte, 32)
	rtKey := make([]byte, 32)
	if _, err := rand.Read(atKey); err != nil {
		panic(fmt.Errorf("unable to generate access-token key: %w", err))
	}
	if _, err := rand.Read(rtKey); err != nil {
		panic(fmt.Errorf("unable to generate refresh-token key: %w", err))
	}
	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), atKey)
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), rtKey)

	// Services. Device and CIBA sessions are wired because the token
	// service requires them, even though no proto RPC exposes those flows
	// through this gRPC surface yet.
	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authzdetails.NewStaticValidator(map[string]struct{}{authDetailsType: {}}))
	tokenz := token.New(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources)

	// Dynamic client registration (RFC 7591) is operator-gated: deny by
	// default, enable with SOLID_EXAMPLE_DCR_ENABLED=true. RFC 7592
	// management (Read/Update/Delete) rides the same gate: no registration
	// means no registration access token, so management calls fail closed.
	registrz := clientregistration.New(clients, tokens, func(context.Context, *clientv1.RegisterRequest) bool {
		return envOr("SOLID_EXAMPLE_DCR_ENABLED", "false") == "true"
	})

	// The AS issuer advertised by the backend is the public issuer of the
	// presentation layer in front of it; the gRPC listen address is a
	// separate, private surface.
	issuer := envOr("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")

	// SPIFFE trust bundles (draft-ietf-oauth-spiffe-client-auth-02
	// section 6): the example.org trust domain keys are pre-configured
	// statically.
	spiffeBundleSet := jwk.NewSet()
	_ = spiffeBundleSet.Set("keys", []jwk.Key{func() jwk.Key {
		k := spiffedemo.JWTSVIDPublicKey()
		_ = k.Set(jwk.KeyUsageKey, spiffe.KeyUseJWTSVID)
		return k
	}()})
	spiffeBundles := spiffe.NewStaticBundleSource(map[string]jwk.Set{
		spiffedemo.TrustDomain: spiffeBundleSet,
	})

	// Assemble the gRPC server surface.
	srv := grpc.NewServer()
	flowv1.RegisterAuthorizationServiceServer(srv, grpckit.AuthorizationService(authz, tokenz))
	clientv1.RegisterClientAuthenticationServiceServer(srv, grpckit.ClientAuthentication(clients, issuer, clientAssertionAlgorithms, spiffeBundles, proofs, profile.Strict()))
	clientv1.RegisterClientRegistrationServiceServer(srv, grpckit.ClientRegistration(registrz, issuer))
	clientv1.RegisterClientRegistrationManagementServiceServer(srv, grpckit.ClientRegistrationManagement(registrz, issuer))
	tokenv1.RegisterIntrospectionServiceServer(srv, grpckit.IntrospectionService(tokenz))
	tokenv1.RegisterRevocatonServiceServer(srv, grpckit.RevocationService(tokenz))

	listenAddr := envOr("SOLID_EXAMPLE_GRPC_LISTEN_ADDR", ":9090")
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("gRPC authorization backend listening on", listenAddr)
	log.Fatal(srv.Serve(lis))
}

// envOr reads an environment variable, falling back to def when unset or
// empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

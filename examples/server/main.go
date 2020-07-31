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
	"encoding/json"
	"log"
	"net/http"

	"zntr.io/solid/examples/server/handlers"
	"zntr.io/solid/examples/server/middleware"
	"zntr.io/solid/examples/storage/inmemory"

	"zntr.io/solid/pkg/sdk/dpop"
	"zntr.io/solid/pkg/sdk/generator"
	jwtgen "zntr.io/solid/pkg/sdk/generator/jwt"
	"zntr.io/solid/pkg/sdk/jarm"
	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/jwsreq"
	"zntr.io/solid/pkg/sdk/jwt"
	"zntr.io/solid/pkg/server/authorizationserver"

	"github.com/square/go-jose/v3"
)

var jwkPrivateKey = []byte(`{
		"kty": "EC",
		"d": "-3yrGLfHTjuvcpG8gZzwQoz9P6uWgBW6HTmYTb-f6u4HxK05PpTdheKBdQ1nXkV-",
		"use": "sig",
		"crv": "P-384",
		"kid": "123456789",
		"x": "De4LLFSUCTAAU8O7_ew0VkNR03_kTH9SNCFuhbpi8D1JUbhABRLpNygSDLf2waQt",
		"y": "cEXPFElY6-qb-5xsFu875_58D3lKZlcOzD99ulje6CAh4D_rJjYU7quxf82xCAUZ",
		"alg": "ES384"
	}`)

func keyProvider() jwk.KeyProviderFunc {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(jwkPrivateKey, &privateKey)
	if err != nil {
		panic(err)
	}

	return func(_ context.Context) (*jose.JSONWebKey, error) {
		// No error
		return &privateKey, nil
	}
}

func keySetProvider() jwk.KeySetProviderFunc {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(jwkPrivateKey, &privateKey)
	if err != nil {
		panic(err)
	}

	return func(_ context.Context) (*jose.JSONWebKeySet, error) {
		// No error
		return &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				privateKey.Public(),
			},
		}, nil
	}
}

func main() {
	ctx := context.Background()

	// Prepare the authorization server
	as, err := authorizationserver.New(ctx,
		"http://127.0.0.1:8080", // Issuer
		// Client storage
		authorizationserver.ClientReader(inmemory.Clients()),
		// Authorization requests
		authorizationserver.AuthorizationRequestManager(inmemory.AuthorizationRequests()),
		// Authorization code storage
		authorizationserver.AuthorizationCodeSessionManager(inmemory.AuthorizationCodeSessions()),
		// Token storage
		authorizationserver.TokenManager(inmemory.Tokens()),
		// Access token generator
		authorizationserver.AccessTokenGenerator(jwtgen.AccessToken(jose.ES384, keyProvider())),
		// Device authorization session storage
		authorizationserver.DeviceCodeSessionManager(inmemory.DeviceCodeSessions(generator.DefaultDeviceUserCode())),
	)
	if err != nil {
		panic(err)
	}

	// Create client authentication middleware
	clientAuth := middleware.ClientAuthentication(inmemory.Clients())
	secHeaders := middleware.SecurityHaders()
	basicAuth := middleware.BasicAuthentication()

	// Initialize dpop verifier
	dpopVerifier, err := dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.DefaultVerifier(keySetProvider(), []string{"ES384"}))
	if err != nil {
		panic(err)
	}

	// JWSREQ Decoder
	requestDecoder := jwsreq.JWTAuthorizationDecoder(keySetProvider())

	// Initialize JARM encoder
	jarmEncoder := jarm.JWTEncoder(jose.ES384, keyProvider())

	// Create router
	http.Handle("/.well-known/oauth-authorization-server", handlers.Metadata(as))
	http.Handle("/.well-known/openid-configuration", handlers.Metadata(as))
	http.Handle("/.well-known/jwks.json", handlers.JWKS(as, keySetProvider()))
	http.Handle("/par", middleware.Adapt(handlers.PushedAuthorizationRequest(as, dpopVerifier), clientAuth))
	http.Handle("/authorize", middleware.Adapt(handlers.Authorization(as, inmemory.Clients(), requestDecoder, jarmEncoder), secHeaders, basicAuth))
	http.Handle("/device_authorize", middleware.Adapt(handlers.DeviceAuthorization(as), clientAuth))
	http.Handle("/token", middleware.Adapt(handlers.Token(as, dpopVerifier), clientAuth))
	http.Handle("/token/introspect", middleware.Adapt(handlers.TokenIntrospection(as), clientAuth))
	http.Handle("/token/revoke", middleware.Adapt(handlers.TokenRevocation(as), clientAuth))
	http.Handle("/device", middleware.Adapt(handlers.Device(as), secHeaders, basicAuth))
	http.Handle("/register", handlers.DCR(as))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

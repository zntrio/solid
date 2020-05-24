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

	"go.zenithar.org/solid/examples/server/handlers"
	"go.zenithar.org/solid/examples/server/middleware"
	"go.zenithar.org/solid/examples/storage/inmemory"
	"go.zenithar.org/solid/pkg/authorizationserver"
	"go.zenithar.org/solid/pkg/generator/jwt"

	"github.com/square/go-jose/v3"
)

var (
	jwkPrivateKey = []byte(`{
		"kty": "EC",
		"d": "-3yrGLfHTjuvcpG8gZzwQoz9P6uWgBW6HTmYTb-f6u4HxK05PpTdheKBdQ1nXkV-",
		"use": "sig",
		"crv": "P-384",
		"kid": "123456789",
		"x": "De4LLFSUCTAAU8O7_ew0VkNR03_kTH9SNCFuhbpi8D1JUbhABRLpNygSDLf2waQt",
		"y": "cEXPFElY6-qb-5xsFu875_58D3lKZlcOzD99ulje6CAh4D_rJjYU7quxf82xCAUZ",
		"alg": "ES384"
	}`)
)

func keyProvider() jwt.KeyProviderFunc {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(jwkPrivateKey, &privateKey)
	if err != nil {
		panic(err)
	}

	return func() (*jose.JSONWebKey, error) {
		// No error
		return &privateKey, nil
	}
}

func main() {
	var (
		ctx = context.Background()
	)

	// Prepare the authorization server
	as := authorizationserver.New(ctx,
		"http://localhost:8080", // Issuer
		authorizationserver.ClientReader(inmemory.Clients()),
		authorizationserver.AuthorizationRequestManager(inmemory.AuthorizationRequests()),
		authorizationserver.AuthorizationCodeSessionManager(inmemory.AuthorizationCodeSessions()),
		authorizationserver.TokenManager(inmemory.Tokens()),
		authorizationserver.AccessTokenGenerator(jwt.AccessToken(jose.ES384, keyProvider())),
	)

	// Create client authentication middleware
	clientAuth := middleware.ClientAuthentication(inmemory.Clients())
	secHeaders := middleware.SecurityHaders()
	basicAuth := middleware.BasicAuthentication()

	// Create router
	http.Handle("/.well-known/openid-configuration", handlers.Metadata("http://localhost:8080"))
	http.Handle("/par", middleware.Adapt(handlers.PushedAuthorizationRequest(as), clientAuth))
	http.Handle("/authorize", middleware.Adapt(handlers.Authorization(as), secHeaders, basicAuth))
	http.Handle("/token", middleware.Adapt(handlers.Token(as), clientAuth))
	http.Handle("/token/introspect", middleware.Adapt(handlers.TokenIntrospection(as), clientAuth))
	http.Handle("/token/revoke", middleware.Adapt(handlers.TokenRevocation(as), clientAuth))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

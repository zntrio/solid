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
	"log"
	"net/http"

	"go.zenithar.org/solid/examples/server/handlers"
	"go.zenithar.org/solid/examples/server/middleware"
	"go.zenithar.org/solid/examples/storage/inmemory"
	"go.zenithar.org/solid/pkg/authorizationserver"
)

func main() {
	var (
		ctx = context.Background()
	)

	// Prepare the authorization server
	as := authorizationserver.New(ctx,
		"http://localhost:8080", // Issuer
		authorizationserver.ClientReader(inmemory.Clients()),
		authorizationserver.AuthorizationRequestManager(inmemory.AuthorizationRequests()),
		authorizationserver.SessionManager(inmemory.Sessions()),
		authorizationserver.TokenManager(inmemory.Tokens()),
	)

	// Create client authentication middleware
	clientAuth := middleware.ClientAuthentication(inmemory.Clients())

	// Create router
	http.Handle("/.well-known/openid-configuration", handlers.Metadata("http://localhost:8080"))
	http.Handle("/par", middleware.Adapt(handlers.PushedAuthorizationRequest(as), clientAuth))
	http.Handle("/authorize", handlers.Authorization(as))
	http.Handle("/token", middleware.Adapt(handlers.Token(as), clientAuth))
	http.Handle("/token/introspect", middleware.Adapt(handlers.TokenIntrospection(as), clientAuth))
	http.Handle("/token/revoke", middleware.Adapt(handlers.TokenRevocation(as), clientAuth))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

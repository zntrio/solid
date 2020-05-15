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

package oidc

import (
	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/internal/reactor/oidc/core"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/authorizationserver/features"
	"go.zenithar.org/solid/pkg/reactor"
)

// Core enable basic features.
func Core() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token) {
		// Register authorization request handler.
		r.RegisterHandler(&corev1.AuthorizationRequest{}, core.AuthorizeHandler(authorizations))
		// REgister token request handler.
		r.RegisterHandler(&corev1.TokenRequest{}, core.GetTokenHandler(tokens))
	}
}

// Introspection enable token introspection features.
func Introspection() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token) {
		// Register intropection request handler.
		r.RegisterHandler(&corev1.TokenIntrospectionRequest{}, core.IntrospectionHandler(tokens))
	}
}

// Revocation enable token revocation features.
func Revocation() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token) {
		// Register revocation request handler.
		r.RegisterHandler(&corev1.TokenRevocationRequest{}, core.RevocationHandler(tokens))
	}
}

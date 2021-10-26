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
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/internal/reactor/oidc/core"
	"zntr.io/solid/internal/services"
	"zntr.io/solid/pkg/server/authorizationserver/features"
	"zntr.io/solid/pkg/server/reactor"
)

// Core enable basic features.
func Core() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token, devices services.Device) {
		// Register authorization request handler.
		r.RegisterHandler(&corev1.AuthorizationCodeRequest{}, core.AuthorizeHandler(authorizations))
		// REgister token request handler.
		r.RegisterHandler(&corev1.TokenRequest{}, core.GetTokenHandler(tokens))
	}
}

// Introspection enable token introspection features.
func Introspection() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token, devices services.Device) {
		// Register intropection request handler.
		r.RegisterHandler(&corev1.TokenIntrospectionRequest{}, core.IntrospectionHandler(tokens))
	}
}

// Revocation enable token revocation features.
func Revocation() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token, devices services.Device) {
		// Register revocation request handler.
		r.RegisterHandler(&corev1.TokenRevocationRequest{}, core.RevocationHandler(tokens))
	}
}

// Device enable device grant flow features.
func Device() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token, devices services.Device) {
		// Register device authorization request handler.
		r.RegisterHandler(&corev1.DeviceAuthorizationRequest{}, core.DeviceAuthorizeHandler(devices))
		// Register user code validation request handler.
		r.RegisterHandler(&corev1.DeviceCodeValidationRequest{}, core.UserCodeValidationHandler(devices))
	}
}

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
	"zntr.io/solid/internal/reactor/oidc/par"
	"zntr.io/solid/internal/services"
	"zntr.io/solid/pkg/server/authorizationserver/features"
	"zntr.io/solid/pkg/server/reactor"
)

// PushedAuthorizationRequest enables pushed authorization requetst related features.
func PushedAuthorizationRequest() features.Feature {
	return func(r reactor.Reactor, authorizations services.Authorization, _ services.Token, _ services.Device, _ services.Client) {
		// Register authorization registration handler.
		r.RegisterHandler(&corev1.RegistrationRequest{}, par.RegisterAuthorizationHandler(authorizations))
	}
}

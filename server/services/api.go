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

package services

import (
	"context"

	corev1 "zntr.io/solid/api/oidc/core/v1"
)

// Authorization describes authorization request processor.
type Authorization interface {
	// Authorize a request.
	Authorize(ctx context.Context, req *corev1.AuthorizationCodeRequest) (*corev1.AuthorizationCodeResponse, error)
	// Register a request.
	Register(ctx context.Context, req *corev1.RegistrationRequest) (*corev1.RegistrationResponse, error)
}

// Token describes token request processor.
type Token interface {
	// Token handles token retrieval.
	Token(ctx context.Context, req *corev1.TokenRequest) (*corev1.TokenResponse, error)
	// Introspect handles token introspection.
	Introspect(ctx context.Context, req *corev1.TokenIntrospectionRequest) (*corev1.TokenIntrospectionResponse, error)
	// Revoke given token.
	Revoke(ctx context.Context, req *corev1.TokenRevocationRequest) (*corev1.TokenRevocationResponse, error)
}

// Device authorization service contract.
type Device interface {
	// Authorize process device authorization request.
	Authorize(ctx context.Context, req *corev1.DeviceAuthorizationRequest) (*corev1.DeviceAuthorizationResponse, error)
	// Validate user code
	Validate(ctx context.Context, req *corev1.DeviceCodeValidationRequest) (*corev1.DeviceCodeValidationResponse, error)
}

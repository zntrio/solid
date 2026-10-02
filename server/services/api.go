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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// Authorization describes authorization request processor.
type Authorization interface {
	// Authorize a request.
	Authorize(ctx context.Context, req *flowv1.AuthorizeRequest) (*flowv1.AuthorizeResponse, error)
	// Register a request.
	Register(ctx context.Context, req *flowv1.RegistrationRequest) (*flowv1.RegistrationResponse, error)
}

// Token describes token request processor.
type Token interface {
	// Token handles token retrieval.
	Token(ctx context.Context, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error)
	// Introspect handles token introspection.
	Introspect(ctx context.Context, req *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error)
	// Revoke given token.
	Revoke(ctx context.Context, req *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error)
}

// Device authorization service contract.
type Device interface {
	// Authorize process device authorization request.
	Authorize(ctx context.Context, req *flowv1.DeviceAuthorizationRequest) (*flowv1.DeviceAuthorizationResponse, error)
	// Validate user code
	Validate(ctx context.Context, req *flowv1.DeviceCodeValidationRequest) (*flowv1.DeviceCodeValidationResponse, error)
	// Deny user code (RFC 8628 section 3.5: access_denied).
	Deny(ctx context.Context, req *flowv1.DeviceCodeValidationRequest) (*flowv1.DeviceCodeValidationResponse, error)
}

// Backchannel authentication service contract (OpenID CIBA Core 1.0).
type BackchannelAuthentication interface {
	// Authorize process a backchannel authentication request (CIBA section 7).
	Authorize(ctx context.Context, req *flowv1.BackchannelAuthenticationRequest) (*flowv1.BackchannelAuthenticationResponse, error)
	// Validate completes the end-user approval on the authentication device (CIBA section 8).
	Validate(ctx context.Context, req *flowv1.BackchannelAuthenticationValidationRequest) (*flowv1.BackchannelAuthenticationValidationResponse, error)
	// Deny refuses a backchannel authentication request (CIBA section 11: access_denied).
	Deny(ctx context.Context, req *flowv1.BackchannelAuthenticationValidationRequest) (*flowv1.BackchannelAuthenticationValidationResponse, error)
}

// ClientRegistration describes dynamic client registration processor
// (RFC 7591) and the RFC 7592 management protocol.
type ClientRegistration interface {
	// Register a client (RFC 7591 section 3.2.1).
	Register(ctx context.Context, req *clientv1.RegisterRequest) (*clientv1.RegisterResponse, error)
	// Read the current registration (RFC 7592 section 2.1).
	Read(ctx context.Context, req *clientv1.ReadRequest) (*clientv1.ReadResponse, error)
	// Update the registration (RFC 7592 section 2.2).
	Update(ctx context.Context, req *clientv1.UpdateRequest) (*clientv1.UpdateResponse, error)
	// Delete the registration (RFC 7592 section 2.3).
	Delete(ctx context.Context, req *clientv1.DeleteRequest) (*clientv1.DeleteResponse, error)
}

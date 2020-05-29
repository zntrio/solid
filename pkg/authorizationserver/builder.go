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

package authorizationserver

import (
	"context"
	"fmt"
	"net/url"

	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/internal/services/authorization"
	"go.zenithar.org/solid/internal/services/device"
	"go.zenithar.org/solid/internal/services/token"
	"go.zenithar.org/solid/pkg/authorizationserver/features"
	"go.zenithar.org/solid/pkg/authorizationserver/features/oidc"
	"go.zenithar.org/solid/pkg/generator"
	"go.zenithar.org/solid/pkg/reactor"
	"go.zenithar.org/solid/pkg/request"
)

// AuthorizationServer represents global authorization features enabled at-runtime.
type AuthorizationServer interface {
	Issuer() *url.URL
	Enable(features.Feature)
	Do(ctx context.Context, req interface{}) (interface{}, error)
}

// -----------------------------------------------------------------------------

// New assemble all given options to instanciate an authorization server.
func New(ctx context.Context, issuer string, opts ...Option) (AuthorizationServer, error) {
	// Default options
	defaultOptions := &options{
		authorizationCodeGenerator:      generator.DefaultAuthorizationCode(),
		accessTokenGenerator:            generator.DefaultToken(),
		refreshTokenGenerator:           generator.DefaultToken(),
		authorizationRequestDecoder:     request.JWSAuthorizationDecoder(),
		clientReader:                    nil,
		tokenManager:                    nil,
		authorizationCodeSessionManager: nil,
		deviceCodeSessionManager:        nil,
	}

	// Parse issuer
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer must be a valid URL")
	}

	// Parse options
	for _, o := range opts {
		o(defaultOptions)
	}

	// Initialize services
	authorizations := authorization.New(defaultOptions.clientReader, defaultOptions.authorizationRequestManager, defaultOptions.authorizationCodeSessionManager, defaultOptions.authorizationRequestDecoder)
	devices := device.New(defaultOptions.clientReader, defaultOptions.deviceCodeSessionManager)
	tokens := token.New(defaultOptions.accessTokenGenerator, defaultOptions.idTokenGenerator, defaultOptions.clientReader, defaultOptions.authorizationRequestManager, defaultOptions.authorizationCodeSessionManager, defaultOptions.deviceCodeSessionManager, defaultOptions.tokenManager)

	// Wire message
	as := &authorizationServer{
		issuer:         issuerURL,
		authorizations: authorizations,
		tokens:         tokens,
		devices:        devices,
		r:              reactor.New(issuer),
		dopts:          defaultOptions,
	}

	// Enable default features
	as.Enable(oidc.Core())
	as.Enable(oidc.Introspection())
	as.Enable(oidc.PushedAuthorizationRequest())
	as.Enable(oidc.Revocation())
	as.Enable(oidc.Device())

	// Return Authorization Server instance
	return as, nil
}

type authorizationServer struct {
	issuer         *url.URL
	authorizations services.Authorization
	tokens         services.Token
	devices        services.Device
	r              reactor.Reactor
	dopts          *options
}

func (as *authorizationServer) Issuer() *url.URL {
	return as.issuer
}

func (as *authorizationServer) Enable(f features.Feature) {
	f(as.r, as.authorizations, as.tokens, as.devices)
}

func (as *authorizationServer) Do(ctx context.Context, req interface{}) (interface{}, error) {
	return as.r.Do(ctx, req)
}

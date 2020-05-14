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
	"go.zenithar.org/solid/pkg/authorization"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/token"
)

// Builder options holder
type options struct {
	authorizationCodeGenerator  authorization.CodeGenerator
	clientReader                storage.ClientReader
	authorizationRequestManager storage.AuthorizationRequest
	accessTokenGenerator        token.AccessTokenGenerator
	idTokenGenerator            token.IDTokenGenerator
	sessionManager              storage.Session
	tokenManager                storage.Token
}

// Option defines functional pattern function type contract.
type Option func(*options)

// ClientReader defines the implementation for retrieving client details.
func ClientReader(store storage.ClientReader) Option {
	return func(opts *options) {
		opts.clientReader = store
	}
}

// AuthorizationRequestManager defines the implementation for managing authorization requests.
func AuthorizationRequestManager(store storage.AuthorizationRequest) Option {
	return func(opts *options) {
		opts.authorizationRequestManager = store
	}
}

// SessionManager defines the implementation for managing authorization sessions.
func SessionManager(store storage.Session) Option {
	return func(opts *options) {
		opts.sessionManager = store
	}
}

// TokenManager defines the implementation for managing tokens.
func TokenManager(store storage.Token) Option {
	return func(opts *options) {
		opts.tokenManager = store
	}
}

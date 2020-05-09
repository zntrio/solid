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

	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/authorizationserver/features"
	"go.zenithar.org/solid/pkg/reactor"
)

// AuthorizationServer represents global authorization features enabled at-runtime.
type AuthorizationServer interface {
	Enable(features.Feature)
	Do(ctx context.Context, req interface{}) (interface{}, error)
}

// -----------------------------------------------------------------------------

// New assemble all given options to instanciate an authorization server.
func New(ctx context.Context, issuer string, opts ...Option) AuthorizationServer {
	return &authorizationServer{}
}

type authorizationServer struct {
	authorizations services.Authorization
	tokens         services.Token
	r              reactor.Reactor
}

func (as *authorizationServer) Enable(f features.Feature) {
	f(as.r, as.authorizations, as.tokens)
}

func (as *authorizationServer) Do(ctx context.Context, req interface{}) (interface{}, error) {
	return as.r.Do(ctx, req)
}

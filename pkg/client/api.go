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

package client

import (
	"context"

	"github.com/square/go-jose/v3"
	"golang.org/x/oauth2"

	discoveryv1 "zntr.io/solid/api/gen/go/oidc/discovery/v1"
)

// Client describes OIDC client contract.
type Client interface {
	Assertion() (string, error)
	CreateRequestURI(ctx context.Context, assertion, state string) (*RequestURIResponse, error)
	AuthenticationURL(ctx context.Context, requestURI string) (string, error)
	ExchangeCode(ctx context.Context, assertion, authorizationCode, pkceCodeVerifier string) (*oauth2.Token, error)
	PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, uint64, error)
	ClientID() string
	Audience() string
	ServerMetadata() *discoveryv1.ServerMetadata
}

// Options defines client options
type Options struct {
	Issuer      string
	Audience    string
	ClientID    string
	RedirectURI string
	Scopes      []string
	JWK         []byte
}

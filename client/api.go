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
	"net/http"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/jwk"
)

// Client describes OIDC client contract.
type Client interface {
	Assertion() (string, error)
	PublicKeys(ctx context.Context) (jwk.Set, uint64, error)
	ServerMetadata() *discoveryv1.ServerMetadata
	Introspect(ctx context.Context, assertion, token string) (*tokenv1.Token, error)
	ClientCredentials(ctx context.Context, assertion string) (*Token, error)
}

// Options defines client options
type Options struct {
	ClientID string
	JWK      []byte

	// HTTPClient overrides the *http.Client used for metadata, token, and
	// introspection requests (http.DefaultClient when nil). Demos use it
	// to install a transport that prints the protocol flow.
	HTTPClient *http.Client

	// Scope and Resource are sent with the client_credentials grant: the
	// authorization server requires a non-empty scope and a resource
	// indicator (the token audience, RFC 8707) on the minted token.
	Scope    string
	Resource string
}

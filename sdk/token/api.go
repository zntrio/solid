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

package token

import (
	"context"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

// -----------------------------------------------------------------------------

const (
	// TypeAccessToken describes AccessToken header type.
	TypeAccessToken = "at"
	// TypeRefreshToken describes RefreshToken header type.
	TypeRefreshToken = "rt"
	// TypeAuthzRequest describes Authorization Request header type.
	TypeAuthzRequest = "oauth-authz-req"
	// TypeAuthzResponseMode describes Authorization Response Mode header type.
	TypeAuthzResponseMode = "jarm"
	// TypeDPoP describes DPoP header type.
	TypeDPoP = "dpop"
	// TypeClientAssertion describes client assertion header type.
	TypeClientAssertion = "client-assertion"
	// TypeTokenInstrospection describes token instrospection response header type.
	TypeTokenInstrospection = "token-introspection"
	// TypeServerMetadata describes authorization server metdata response header type.
	TypeServerMetadata = "oauth-authorization-server"
)

// -----------------------------------------------------------------------------

//go:generate mockgen -destination mock/generator.gen.go -package mock zntr.io/solid/sdk/token Generator

// Generator describes claims generator contract.
type Generator interface {
	Generate(ctx context.Context, t *corev1.Token) (string, error)
}

//go:generate mockgen -destination mock/serializer.gen.go -package mock zntr.io/solid/sdk/token Serializer

// Serializer describes Token claims serializer contract.
type Serializer interface {
	Serialize(ctx context.Context, claims any) (string, error)
	ContentType() string
}

// Encrypter describes token encryption contract.
type Encrypter interface {
	Encrypt(ctx context.Context, contentType, token string, aad []byte) (string, error)
}

//go:generate mockgen -destination mock/verifier.gen.go -package mock zntr.io/solid/sdk/token Verifier

// Verifier describes Token verifier contract.
type Verifier interface {
	Parse(token string) (Token, error)
	Verify(token string) error
	Claims(ctx context.Context, token string, claims any) error
}

//go:generate mockgen -destination mock/token.gen.go -package mock zntr.io/solid/sdk/token Token

// Token represents a token contract.
type Token interface {
	Algorithm() (string, error)
	Type() (string, error)
	KeyID() (string, error)
	PublicKey() (any, error)
	PublicKeyThumbPrint() (string, error)
	Claims(publicKey any, claims any) error
}

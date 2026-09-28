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

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// -----------------------------------------------------------------------------

const (
	// TypeAccessToken describes AccessToken header type.
	TypeAccessToken = "at"
	// TypeRefreshToken describes RefreshToken header type.
	TypeRefreshToken = "rt"
	// TypeAuthzRequest describes Authorization Request header type.
	TypeAuthzRequest = "oauth-authz-req"
	// TypeAuthzResponseMode describes Authorization Response Mode header
	// type (RFC 8725 section 3.11 typ confusion: the value must match what
	// the JARM decoder accepts, "jarm+jwt").
	TypeAuthzResponseMode = "jarm"
	// TypeDPoP describes DPoP proof header type, as required by
	// RFC 9449 section 4.1.
	TypeDPoP = "dpop"
	// TypeClientAssertion describes client assertion header type.
	TypeClientAssertion = "client-assertion"
	// TypeTokenIntrospection describes token introspection response
	// header type.
	TypeTokenIntrospection = "token-introspection"
	// TypeServerMetadata describes authorization server metadata response
	// header type.
	TypeServerMetadata = "oauth-authorization-server"
	// TypeIDJAG is the base typ value of an ID-JAG
	// (draft-ietf-oauth-identity-assertion-authz-grant-04, section 3.1,
	// per RFC 8725 section 3.11). The serializer appends its media-type
	// suffix: a JWT-serialized ID-JAG carries typ "oauth-id-jag+jwt".
	TypeIDJAG = "oauth-id-jag"
)

// HeaderType derives the typ value of a signed token from its base type
// and serialization format. Serializers follow the RFC 8725 section 3.11
// media-type convention: the JWT serializer emits "<base>+jwt" and the
// CWT serializer "<base>+cwt"; PASETO carries the base type in its
// footer unchanged.
func HeaderType(base, contentType string) string {
	switch contentType {
	case "JWT":
		return base + "+jwt"
	case "CWT":
		return base + "+cwt"
	default:
		return base
	}
}

// -----------------------------------------------------------------------------

//go:generate mockgen -destination mock/generator.gen.go -package mock zntr.io/solid/sdk/token Generator

// Generator describes claims generator contract.
type Generator interface {
	Generate(ctx context.Context, t *tokenv1.Token) (string, error)
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
	// ContentType returns the serialization format the verifier parses
	// ("JWT", "CWT", "PASETO"): paired with token.HeaderType it derives
	// the typ value a token of the given base type must carry.
	ContentType() string
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
	// UnverifiedClaims decodes the token claims without any signature
	// verification. The values are attacker-controlled: callers MUST
	// only use them to route key resolution (e.g. by issuer identifier),
	// never to accept or reject an assertion. Verification-grade claim
	// values come exclusively from Claims.
	UnverifiedClaims(claims any) error
}

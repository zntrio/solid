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

package jwt

import (
	"fmt"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// AccessTokenSigner represents JWT Access Token signer.
func AccessTokenSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeAccessToken, alg, keyProvider)
}

// RefreshTokenSigner represents JWT Refresh Token signer.
func RefreshTokenSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeRefreshToken, alg, keyProvider)
}

// RequestSigner represents JWT Request Token signer.
func RequestSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeAuthzRequest, alg, keyProvider)
}

// JARMSigner represents JWT JARM Token signer.
func JARMSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeAuthzResponseMode, alg, keyProvider)
}

// DPoPSigner represents JWT DPoP Token signer.
func DPoPSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   fmt.Sprintf("%s+jwt", token.TypeDPoP),
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    true,
	}
}

// ClientAssertionSigner represents JWT Client Assertion signer.
func ClientAssertionSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeClientAssertion, alg, keyProvider)
}

// TokenIntrospection represents JWT Token Introspection Assertion signer.
func TokenIntrospection(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeTokenIntrospection, alg, keyProvider)
}

// ServerMetadata represents JWT Server Metadata Assertion signer.
func ServerMetadata(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeServerMetadata, alg, keyProvider)
}

// IDJAG represents JWT ID-JAG.
func IDJAG(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return TypedSigner(token.TypeIDJAG, alg, keyProvider)
}

// TypedSigner returns a JWT signer with an explicit typ header value, for
// mechanisms defining their own token type (e.g. the ID-JAG profile
// "oauth-id-jag+jwt"). The alg allowlist is the caller's responsibility:
// assemblies must pass an elliptic-curve or ML-DSA identifier.
func TypedSigner(tokenType, alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   fmt.Sprintf("%s+jwt", tokenType),
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

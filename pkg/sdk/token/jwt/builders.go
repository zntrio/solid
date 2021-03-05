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
	"github.com/square/go-jose/v3"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// AccessTokenSigner represents JWT Access Token signer.
func AccessTokenSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "at",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// RefreshTokenSigner represents JWT Refresh Token signer.
func RefreshTokenSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "rt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// RequestSigner represents JWT Request Token signer.
func RequestSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "oauth-authz-req",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// JARMSigner represents JWT JARM Token signer.
func JARMSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "jarm",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// DPoPSigner represents JWT DPoP Token signer.
func DPoPSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "dpop",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    true,
	}
}

// ClientAssertionSigner represents JWT Client Assertion signer.
func ClientAssertionSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "client-assertion",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// TokenIntrospectionSigner represents JWT Token Introspection Assertion signer.
func TokenIntrospectionSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "token-introspection",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// ServerMetadataSigner represents JWT Server Metadata Assertion signer.
func ServerMetadataSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   "oauth-authorization-server",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

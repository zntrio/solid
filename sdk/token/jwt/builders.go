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
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// AccessTokenSigner represents JWT Access Token signer.
func AccessTokenSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAccessToken,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// RefreshTokenSigner represents JWT Refresh Token signer.
func RefreshTokenSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeRefreshToken,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// RequestSigner represents JWT Request Token signer.
func RequestSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAuthzRequest,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// JARMSigner represents JWT JARM Token signer.
func JARMSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAuthzResponseMode,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// DPoPSigner represents JWT DPoP Token signer.
func DPoPSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeDPoP,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    true,
	}
}

// ClientAssertionSigner represents JWT Client Assertion signer.
func ClientAssertionSigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeClientAssertion,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// TokenIntrospection represents JWT Token Introspection Assertion signer.
func TokenIntrospection(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeTokenInstrospection,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// ServerMetadata represents JWT Server Metadata Assertion signer.
func ServerMetadata(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeServerMetadata,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// MLDSASigner represents a JWT signer using a post-quantum ML-DSA key
// (FIPS 204, draft-ietf-cose-dilithium). alg must be one of MLDSA44,
// MLDSA65 or MLDSA87; the key provider must return an *MLDSAKey built
// with NewMLDSAKey.
func MLDSASigner(alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAccessToken,
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

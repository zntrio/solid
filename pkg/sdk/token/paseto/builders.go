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

package paseto

import (
	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// AccessTokenSigner represents Paseto Access Token signer.
func AccessTokenSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAccessToken,
		keyProvider: keyProvider,
	}
}

// RefreshTokenSigner represents Paseto Refresh Token signer.
func RefreshTokenSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeRefreshToken,
		keyProvider: keyProvider,
	}
}

// RequestSigner represents Paseto Request Token signer.
func RequestSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAuthzRequest,
		keyProvider: keyProvider,
	}
}

// JARMSigner represents Paseto JARM Token signer.
func JARMSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeAuthzResponseMode,
		keyProvider: keyProvider,
	}
}

// DPoPSigner represents Paseto DPoP Token signer.
func DPoPSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeDPoP,
		keyProvider: keyProvider,
	}
}

// ClientAssertionSigner represents Paseto Client Assertion signer.
func ClientAssertionSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeClientAssertion,
		keyProvider: keyProvider,
	}
}

// TokenIntrospectionSigner represents Paseto Token Introspection Assertion signer.
func TokenIntrospectionSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeTokenInstrospection,
		keyProvider: keyProvider,
	}
}

// ServerMetadataSigner represents Paseto Server Metadata Assertion signer.
func ServerMetadataSigner(keyProvider jwk.KeyProviderFunc) token.Serializer {
	return &defaultSigner{
		tokenType:   token.TypeServerMetadata,
		keyProvider: keyProvider,
	}
}

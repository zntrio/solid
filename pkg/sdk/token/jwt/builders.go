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
	"gopkg.in/square/go-jose.v2"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// AccessTokenSigner represents JWT Access Token signer.
func AccessTokenSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "at+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// RefreshTokenSigner represents JWT Refresh Token signer.
func RefreshTokenSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "rt+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// RequestSigner represents JWT Request Token signer.
func RequestSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "oauth-authz-req+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// JARMSigner represents JWT JARM Token signer.
func JARMSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "jarm+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// DPoPSigner represents JWT DPoP Token signer.
func DPoPSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "dpop+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    true,
	}
}

// ClientAssertionSigner represents JWT Client Assertion signer.
func ClientAssertionSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "client-assertion+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// TokenIntrospection represents JWT Token Introspection Assertion signer.
func TokenIntrospection(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "token-introspection+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

// ServerMetadata represents JWT Server Metadata Assertion signer.
func ServerMetadata(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "oauth-authorization-server+jwt",
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

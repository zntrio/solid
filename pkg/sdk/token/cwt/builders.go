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

package cwt

import (
	"go.mozilla.org/cose"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// AccessTokenSigner represents CWT Access Token signer.
func AccessTokenSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "at+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// RefreshTokenSigner represents CWT Refresh Token signer.
func RefreshTokenSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "rt+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// RequestSigner represents CWT Request Token signer.
func RequestSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "oauth-authz-req+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// JARMSigner represents CWT JARM Token signer.
func JARMSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "jarm+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// DPoPSigner represents CWT DPoP Token signer.
func DPoPSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "dpop+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// ClientAssertionSigner represents CWT Client Assertion signer.
func ClientAssertionSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "client-assertion+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// TokenIntrospection represents CWT Token Introspection Assertion signer.
func TokenIntrospection(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "token-introspection+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

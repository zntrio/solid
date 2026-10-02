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
	if err := enforceSignAlgorithmAllowlist(alg); err != nil {
		panic(err)
	}
	return &defaultSigner{
		tokenType:   token.HeaderType(token.TypeDPoP, "JWT"),
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

// supportedSignAlgorithms is the JOSE signing algorithm allowlist for the
// JWT signer: elliptic curves and ML-DSA only, no RSA / HS families and
// no "none" (project security posture, RFC 8725 section 3.5).
var supportedSignAlgorithms = map[string]struct{}{
	"ES256": {}, "ES384": {}, "ES512": {},
	"EdDSA":     {},
	jwk.MLDSA44: {}, jwk.MLDSA65: {}, jwk.MLDSA87: {},
}

// enforceSignAlgorithmAllowlist rejects any signing algorithm outside the
// supported elliptic-curve / ML-DSA set.
func enforceSignAlgorithmAllowlist(alg string) error {
	if _, ok := supportedSignAlgorithms[alg]; !ok {
		return fmt.Errorf("unsupported signing algorithm %q", alg)
	}
	return nil
}

// TypedSigner returns a JWT signer with an explicit typ header value, for
// mechanisms defining their own token type (e.g. the ID-JAG profile
// "oauth-id-jag+jwt"). The alg allowlist is enforced at construction
// time: insecure configurations are not offered as options, no RSA / HS /
// none signer can be assembled.
func TypedSigner(tokenType, alg string, keyProvider jwk.KeyProviderFunc) token.Serializer {
	// Fail fast on insecure algorithms: a signer built with an
	// out-of-allowlist alg is a programming error, not a runtime input.
	if err := enforceSignAlgorithmAllowlist(alg); err != nil {
		panic(err)
	}
	return &defaultSigner{
		tokenType:   token.HeaderType(tokenType, "JWT"),
		alg:         alg,
		keyProvider: keyProvider,
		embedJWK:    false,
	}
}

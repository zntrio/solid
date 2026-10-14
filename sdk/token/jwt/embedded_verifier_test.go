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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// TestEmbeddedKeyVerifierRejectsPrivateKeyJWK pins RFC 9449 section 4.3
// check 7: a DPoP proof whose jwk header carries PRIVATE key material is
// rejected explicitly, not incidentally through a crypto-layer type
// mismatch. The harm is the leak: a private key in the header discloses
// the signer's key material to every verifier it talks to.
func TestEmbeddedKeyVerifierRejectsPrivateKeyJWK(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwxjwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwxjwk.AlgorithmKey, "ES256"))

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"jti": "private-jwk-probe",
		"htm": "POST",
		"htu": "https://as.example.org/token",
		"iat": 1700000000,
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = privJWK
	proof, err := tok.SignedString(priv)
	require.NoError(t, err)

	// Sanity: the serialized header really carries the private d member.
	parts := splitCompact(t, proof)
	var hdr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(decodeSegment(t, parts[0]), &hdr))
	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(hdr["jwk"], &members))
	_, hasD := members["d"]
	require.True(t, hasD, "scratch setup: header jwk must carry private d")

	verifier := EmbeddedKeyVerifier([]string{"ES256"})
	var claims map[string]any
	err = verifier.Claims(t.Context(), proof, &claims)
	require.Error(t, err, "private key material in jwk header must be rejected")
}

// TestEmbeddedKeyVerifierRejectsPrivateKeyJWKRawDoc pins the same guard
// against hand-crafted JWK documents (the attacker does not need a JWK
// serializer to put a private member in the header).
func TestEmbeddedKeyVerifierRejectsPrivateKeyJWKRawDoc(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateDoc := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"y":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"d":   "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw",
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"jti": "private-jwk-raw-probe",
		"htm": "POST",
		"htu": "https://as.example.org/token",
		"iat": 1700000000,
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = privateDoc
	proof, err := tok.SignedString(priv)
	require.NoError(t, err)

	verifier := EmbeddedKeyVerifier([]string{"ES256"})
	var claims map[string]any
	err = verifier.Claims(t.Context(), proof, &claims)
	require.Error(t, err, "hand-crafted private jwk header must be rejected")
}

func splitCompact(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func decodeSegment(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

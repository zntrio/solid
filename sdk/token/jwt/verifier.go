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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// contentTypeJWT is the ContentType of the JWT serializer and verifiers,
// paired with token.HeaderType to derive typ header values.
const contentTypeJWT = "JWT"

// decodeHeader base64-decodes the JWS header segment of a compact token
// and unmarshals it into a gojwt.Token shell (header, method, signature).
// No claim values are exposed by this call: the payload segment is left
// untouched — every claim read goes through signature-verified parsing
// (gojwt.Parser.Parse) in Claims.
func decodeHeader(raw string, supportedAlgorithms []string) (*gojwt.Token, []string, error) {
	// Split the compact form: header.payload.signature.
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("token is not a compact JWS")
	}

	// Decode the header segment only.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode token header: %w", err)
	}
	var header map[string]any
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("unable to decode token header: %w", err)
	}

	// Resolve the signing method from the alg header.
	alg, _ := header["alg"].(string)
	method := gojwt.GetSigningMethod(alg)
	if method == nil {
		return nil, nil, fmt.Errorf("token signed with unknown algorithm %q", alg)
	}

	// Enforce the algorithm allowlist.
	supported := false
	for _, a := range supportedAlgorithms {
		if a == method.Alg() {
			supported = true
			break
		}
	}
	if !supported {
		return nil, nil, fmt.Errorf("token signed with unsupported algorithm %q", method.Alg())
	}

	// Decode the signature segment (payload is deliberately not decoded).
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode token signature: %w", err)
	}

	// Build the token shell carrying header + method + signature; the
	// claims map stays empty until a verifying Parse fills it.
	t := &gojwt.Token{
		Header:    header,
		Method:    method,
		Signature: signature,
		Claims:    gojwt.MapClaims{},
	}

	// No error
	return t, parts, nil
}

// decodeClaims base64-decodes parts[1] and unmarshals into claims.
func decodeClaims(parts []string, claims any) error {
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("unable to decode token claims: %w", err)
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("unable to unmarshal token claims: %w", err)
	}
	return nil
}

// DefaultVerifier declares a default JWT verifier. The algorithm allowlist
// is validated at construction time, mirroring the signer side: assembling
// a verifier that accepts an out-of-allowlist algorithm is a programming
// error, not a runtime input.
func DefaultVerifier(keySetProvider jwk.KeySetProviderFunc, supportedAlgorithms []string) token.Verifier {
	for _, alg := range supportedAlgorithms {
		if err := enforceSignAlgorithmAllowlist(alg); err != nil {
			panic(err)
		}
	}
	return &defaultVerifier{
		keySetProvider:      keySetProvider,
		supportedAlgorithms: supportedAlgorithms,
	}
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	keySetProvider      jwk.KeySetProviderFunc
	supportedAlgorithms []string
}

func (v *defaultVerifier) Parse(raw string) (token.Token, error) {
	// Parse JWT token
	t, parts, err := decodeHeader(raw, v.supportedAlgorithms)
	if err != nil {
		return nil, errors.New("unable to parse signed token")
	}

	// Wrap token instance
	return &tokenAdapter{
		token: t,
		parts: parts,
	}, nil
}

// Verify checks the token signature against the verifier key set.
func (v *defaultVerifier) Verify(raw string) error {
	return v.Claims(context.Background(), raw, &struct{}{})
}

func (v *defaultVerifier) ContentType() string {
	return contentTypeJWT
}

// Claims verifies the token signature against the verifier key set and
// extracts the verified claims.
//
// Verification goes through the golang-jwt parser (WithValidMethods
// enforces the algorithm allowlist): each candidate key from the key set
// is attempted until one verifies. kid routing narrows the candidates when
// the token header carries a kid present in the set.
func (v *defaultVerifier) Claims(ctx context.Context, raw string, claims any) error {
	// Retrieve KeySet
	jwks, err := v.keySetProvider(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve KeySet: %w", err)
	}

	// Resolve candidate signing keys, honoring kid routing when the
	// token carries one present in the key set.
	keys := candidateSigningKeys(jwks)
	routed, errRoute := routeOnKid(raw, jwks)
	switch {
	case errRoute != nil:
		return token.ErrInvalidTokenSignature
	case len(routed) > 0:
		keys = routed
	}

	// Attempt verification with each candidate key through the
	// standard verifying parser.
	// Claims validation (exp/nbf) stays with the caller: temporal
	// semantics belong to the token consumers (e.g. JARM decoder, ID-JAG
	// verifier), which own their clock.
	parser := gojwt.NewParser(gojwt.WithValidMethods(v.supportedAlgorithms), gojwt.WithoutClaimsValidation())
	var verified *gojwt.Token
	for _, k := range keys {
		publicKey, errKey := MaterializeSigningKey(k)
		if errKey != nil {
			continue
		}
		parsed, errParse := parser.Parse(raw, func(*gojwt.Token) (any, error) {
			return publicKey, nil
		})
		if errParse == nil && parsed != nil && parsed.Valid {
			verified = parsed
			break
		}
	}
	if verified == nil {
		return token.ErrInvalidTokenSignature
	}

	// Decode the verified claims into the target object.
	if errDecode := decodeVerifiedClaims(verified, claims); errDecode != nil {
		return errDecode
	}

	// No error
	return nil
}

// candidateSigningKeys returns every signing (non-enc) key of the set.
func candidateSigningKeys(jwks jwk.Set) []jwk.Key {
	var keys []jwk.Key
	for i := range jwks.Len() {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}
		if use, hasUse := k.KeyUsage(); hasUse && use == "enc" {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// routeOnKid syntactically resolves the token kid header against the key
// set; an absent or unknown kid yields no candidates (the caller then uses
// every signing key).
func routeOnKid(raw string, jwks jwk.Set) ([]jwk.Key, error) {
	// Decode the header only: kid routing happens before verification,
	// the header values are never trusted beyond key selection.
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("token is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("unable to decode token header: %w", err)
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unable to decode token header: %w", err)
	}
	if header.KID == "" {
		return nil, nil
	}
	k, found := jwks.LookupKeyID(header.KID)
	if !found {
		return nil, nil
	}
	return []jwk.Key{k}, nil
}

// decodeVerifiedClaims unmarshals the parsed claims into the target.
func decodeVerifiedClaims(t *gojwt.Token, claims any) error {
	raw, err := json.Marshal(t.Claims)
	if err != nil {
		return fmt.Errorf("unable to encode verified claims: %w", err)
	}
	if err := json.Unmarshal(raw, claims); err != nil {
		return fmt.Errorf("unable to decode verified claims: %w", err)
	}
	return nil
}

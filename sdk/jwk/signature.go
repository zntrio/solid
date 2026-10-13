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

package jwk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	golangjwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

// ErrInvalidTokenSignature is raised when token is signed with a private key
// where the public key is not known by the keyset.
var ErrInvalidTokenSignature = errors.New("invalid token signature")

// rawPublicKey materializes a key set entry to a native Go public key,
// usable as a golang-jwt verification key. Entries that cannot be
// materialized (unsupported key types, symmetric keys) are reported as
// errors and skipped by the caller.
func rawPublicKey(k Key) (golangjwt.VerificationKey, error) {
	// AKP keys are not supported by jwx; unwrap the raw ML-DSA public key.
	if mk, ok := k.(*MLDSAKey); ok {
		if mk.MLDSPublicKey() == nil {
			return nil, errors.New("ML-DSA key has no public key material")
		}
		return mk.MLDSPublicKey(), nil
	}

	// PublicRawKeyOf exports only public material, refusing symmetric keys.
	raw, err := jwxjwk.PublicRawKeyOf(k)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// ValidateSignature validates the signature of the given raw token string
// using the keys of the given JWKS. Claims are not validated: solid applies
// its own claims validation after signature verification (RFC 7523 order).
func ValidateSignature(jwks Set, tokenString string, supportedAlgorithms []string) error {
	// Check parameters
	if jwks == nil {
		return errors.New("can't process nil jwks")
	}
	if jwks.Len() == 0 {
		return errors.New("can't process empty jwks")
	}
	if tokenString == "" {
		return errors.New("can't process empty token")
	}
	// Solid stronger posture (RFC 8725 section 3, kid injection): when the
	// token header carries a kid and the key set is kid-addressed (its
	// keys carry kids), the kid MUST exist in the set — an unknown kid
	// fails closed instead of falling back to every key. Rotation
	// publishes the new key under its kid before tokens reference it; an
	// unknown kid referencing a non-existent key is a header attack, not
	// a legitimate rotation. A key set whose keys carry no kids cannot be
	// kid-routed (RFC 7515 section 4.1.4: kid is recipient-advisory), and
	// the signature check against the whole set remains the gate.
	if headerKid := headerKidOf(tokenString); headerKid != "" && KeySetIsKidded(jwks) {
		if _, found := jwks.LookupKeyID(headerKid); !found {
			return ErrInvalidTokenSignature
		}
	}

	// Build the list of candidate public keys from the keyset.
	var candidates []golangjwt.VerificationKey
	for i := range jwks.Len() {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}

		// Skip encryption keys.
		if use, ok := k.KeyUsage(); ok && use == "enc" {
			continue
		}

		// Materialize the key to a native Go public key.
		raw, err := rawPublicKey(k)
		if err != nil {
			continue
		}
		candidates = append(candidates, raw)
	}
	if len(candidates) == 0 {
		return ErrInvalidTokenSignature
	}

	// Verify token signature with the keyset, without claims validation.
	token, err := golangjwt.Parse(tokenString, func(_ *golangjwt.Token) (any, error) {
		return golangjwt.VerificationKeySet{Keys: candidates}, nil
	}, golangjwt.WithValidMethods(supportedAlgorithms), golangjwt.WithoutClaimsValidation())
	if err != nil || !token.Valid {
		return ErrInvalidTokenSignature
	}

	// No error
	return nil
}

// headerKidOf decodes the kid of a compact JWS header without any
// verification; the value is used for key routing only.
func headerKidOf(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return ""
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return ""
	}
	return header.KID
}

// keySetIsKidded reports whether the key set carries kids at all: kid
// routing is only meaningful when the set is kid-addressed. A set of
// anonymous keys cannot be routed by kid, so the whole-set signature
// verification remains the only gate.
func KeySetIsKidded(jwks Set) bool {
	for i := range jwks.Len() {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}
		if kid, has := k.KeyID(); has && kid != "" {
			return true
		}
	}
	return false
}

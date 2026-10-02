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
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"
)

type tokenAdapter struct {
	message *cose.Sign1Message
}

func (ta *tokenAdapter) Type() (string, error) {
	if v, ok := ta.message.Headers.Protected[cose.HeaderLabelType]; ok {
		if s, isString := v.(string); isString {
			return s, nil
		}
	}

	return "", fmt.Errorf("unable to retrieve token type")
}

func (ta *tokenAdapter) KeyID() (string, error) {
	// Read kid from the protected header, falling back to the
	// unprotected one.
	var kid []byte
	if v, ok := ta.message.Headers.Protected[cose.HeaderLabelKeyID]; ok {
		if b, isBstr := v.([]byte); isBstr {
			kid = b
		}
	}
	if kid == nil {
		if v, ok := ta.message.Headers.Unprotected[cose.HeaderLabelKeyID]; ok {
			if b, isBstr := v.([]byte); isBstr {
				kid = b
			}
		}
	}
	if len(kid) > 0 {
		return string(kid), nil
	}

	return "", fmt.Errorf("unable to retrieve kid claim from header")
}

// PublicKey returns an error: CWT/COSE carries no embedded JWK header
// parameter. Key binding in CWT lives in the cnf claim (RFC 8747) and is
// handled at the claims level, not at the serialization level.
func (ta *tokenAdapter) PublicKey() (any, error) {
	return nil, fmt.Errorf("cwt tokens do not embed a public key in their header")
}

// PublicKeyThumbPrint returns an error: CWT/COSE carries no embedded JWK
// header parameter to thumbprint (see PublicKey).
func (ta *tokenAdapter) PublicKeyThumbPrint() (string, error) {
	return "", fmt.Errorf("cwt tokens do not embed a public key in their header")
}

func (ta *tokenAdapter) Algorithm() (string, error) {
	alg, err := ta.message.Headers.Protected.Algorithm()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve `alg` claim from header")
	}

	return alg.String(), nil
}

// Claims verifies the token signature against the given key and decodes
// the verified claims. Verification goes through go-cose so the signature
// check and the protected alg header are enforced by the library itself.
func (ta *tokenAdapter) Claims(publicKey, claims any) error {
	// Materialize the public key (a jwk.Key).
	k, ok := publicKey.(jwxjwk.Key)
	if !ok {
		return fmt.Errorf("invalid public key type")
	}
	rawKey, err := materializePublicKey(k)
	if err != nil {
		return fmt.Errorf("unable to materialize public key: %w", err)
	}

	// Resolve the signing algorithm from the protected header.
	alg, err := ta.message.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("token has no algorithm header")
	}

	// Verify through go-cose: the signature and the protected alg header
	// are checked by the library; claims validation (exp/nbf) stays with
	// the caller, which owns the clock.
	verifier, err := cose.NewVerifier(alg, rawKey)
	if err != nil {
		return fmt.Errorf("unable to initialize COSE verifier: %w", err)
	}
	if err := ta.message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("unable to verify token signature: %w", err)
	}

	// Decode the verified claims into the target object.
	if err := cbor.Unmarshal(ta.message.Payload, claims); err != nil {
		return fmt.Errorf("unable to decode verified claims: %w", err)
	}

	return nil
}

// UnverifiedClaims decodes the payload without signature verification:
// the values are attacker-controlled and only usable to route key
// resolution before Claims performs the verification.
func (ta *tokenAdapter) UnverifiedClaims(claims any) error {
	if err := cbor.Unmarshal(ta.message.Payload, claims); err != nil {
		return fmt.Errorf("unable to decode unverified claims: %w", err)
	}
	return nil
}

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
	"context"
	"crypto"
	_ "crypto/sha256" // ECDSA hash functions required by go-cose verifiers
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// DefaultVerifier declares a default CWT verifier for COSE_Sign1 (tag 18)
// objects as defined by RFC 8392 section 7.1. Verification only succeeds
// for algorithms present in supportedAlgorithms.
func DefaultVerifier(keySetProvider jwk.KeySetProviderFunc, supportedAlgorithms []cose.Algorithm) token.Verifier {
	return &defaultVerifier{
		keySetProvider:      keySetProvider,
		supportedAlgorithms: supportedAlgorithms,
	}
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	keySetProvider      jwk.KeySetProviderFunc
	supportedAlgorithms []cose.Algorithm
}

// decodeSign1 base64url-decodes the raw token and unmarshals it as a
// COSE_Sign1_Tagged object. Header values are exposed syntactically only:
// every claim read goes through signature-verified parsing in Claims.
func decodeSign1(raw string) (*cose.Sign1Message, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("unable to parse signed token")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		return nil, errors.New("unable to parse signed token")
	}
	return &msg, nil
}

func (v *defaultVerifier) Parse(raw string) (token.Token, error) {
	msg, err := decodeSign1(raw)
	if err != nil {
		return nil, err
	}

	// Wrap token instance
	return &tokenAdapter{message: msg}, nil
}

// Verify checks the token signature against the verifier key set.
func (v *defaultVerifier) Verify(raw string) error {
	return v.Claims(context.Background(), raw, &struct{}{})
}

func (v *defaultVerifier) ContentType() string {
	return contentTypeCWT
}

// Claims verifies the token signature against the verifier key set and
// extracts the verified claims.
//
// Each candidate key from the key set is attempted through a go-cose
// verifier (which also enforces the protected alg header) until one
// verifies. kid routing narrows the candidates when the token header
// carries a kid present in the set.
func (v *defaultVerifier) Claims(ctx context.Context, raw string, claims any) error {
	// Decode as COSE_Sign1
	msg, err := decodeSign1(raw)
	if err != nil {
		return err
	}

	// Resolve protected algorithm header
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("token has no algorithm header")
	}

	// Enforce the algorithm allowlist
	supported := false
	for _, candidate := range v.supportedAlgorithms {
		if alg == candidate {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("token signed with unsupported algorithm %q", alg.String())
	}

	// Retrieve KeySet
	jwks, err := v.keySetProvider(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve KeySet: %w", err)
	}

	// Resolve candidate signing keys, honoring kid routing when the
	// token carries one present in the key set.
	keys := candidateSigningKeys(jwks)
	if routed := routeOnKid(msg, jwks); len(routed) > 0 {
		keys = routed
	}

	// Attempt verification with each candidate key.
	if !verifyWithAnyKey(msg, keys, alg) {
		return token.ErrInvalidTokenSignature
	}

	// Decode the verified claims into the target object.
	if errDecode := cbor.Unmarshal(msg.Payload, claims); errDecode != nil {
		return fmt.Errorf("unable to decode verified claims: %w", errDecode)
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

// verifyWithAnyKey attempts message verification with each candidate key
// until one verifies. AKP keys (ML-DSA, RFC 9964) verify through the
// external go-cose verifier implementation; every other key materializes
// through the go-cose constructor. Claims validation (exp/nbf) stays with
// the caller: temporal semantics belong to the token consumers, which own
// their clock.
func verifyWithAnyKey(msg *cose.Sign1Message, keys []jwk.Key, alg cose.Algorithm) bool {
	for _, k := range keys {
		var verifier cose.Verifier
		if akp, isAKP := k.(*jwk.MLDSAKey); isAKP {
			v, errVerifier := CoseVerifierMLDSAForKey(akp)
			if errVerifier != nil {
				continue
			}
			verifier = v
		} else {
			publicKey, errKey := materializePublicKey(k)
			if errKey != nil {
				continue
			}
			v, errVerifier := cose.NewVerifier(alg, publicKey)
			if errVerifier != nil {
				continue
			}
			verifier = v
		}
		if errVerify := msg.Verify(nil, verifier); errVerify == nil {
			return true
		}
	}
	return false
}

// routeOnKid syntactically resolves the token kid header against the key
// set; an absent or unknown kid yields no candidates (the caller then uses
// every signing key).
func routeOnKid(msg *cose.Sign1Message, jwks jwk.Set) []jwk.Key {
	// Read kid from the protected header, falling back to the unprotected
	// one. kid values are never trusted beyond key selection.
	var kid []byte
	if v, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]; ok {
		if b, isBstr := v.([]byte); isBstr {
			kid = b
		}
	}
	if kid == nil {
		if v, ok := msg.Headers.Unprotected[cose.HeaderLabelKeyID]; ok {
			if b, isBstr := v.([]byte); isBstr {
				kid = b
			}
		}
	}
	if len(kid) == 0 {
		return nil
	}
	k, found := jwks.LookupKeyID(string(kid))
	if !found {
		return nil
	}
	return []jwk.Key{k}
}

// materializePublicKey converts a jwk key into a native Go public key
// consumable by go-cose verifiers.
func materializePublicKey(k jwk.Key) (crypto.PublicKey, error) {
	pub, err := jwxjwk.PublicKeyOf(k)
	if err != nil {
		return nil, fmt.Errorf("unable to derive public key: %w", err)
	}
	var raw crypto.PublicKey
	if err := jwxjwk.Export(pub, &raw); err != nil {
		return nil, fmt.Errorf("unable to materialize public key: %w", err)
	}
	return raw, nil
}

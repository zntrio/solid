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
	"context"
	"encoding/json"
	"fmt"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

// Field name constants and helpers re-exported from jwx.
const (
	// KeyIDKey is the field name for the kid member.
	KeyIDKey = jwxjwk.KeyIDKey
	// KeyUsageKey is the field name for the use member.
	KeyUsageKey = jwxjwk.KeyUsageKey
	// AlgorithmKey is the field name for the alg member.
	AlgorithmKey = jwxjwk.AlgorithmKey
	// KeyTypeKey is the field name for the kty member.
	KeyTypeKey = jwxjwk.KeyTypeKey
)

// NewSet returns an empty key set.
func NewSet() Set { return jwxjwk.NewSet() }

// AssignKeyID derives the RFC 7638 thumbprint of the key and assigns it
// as the key's kid.
func AssignKeyID(key Key) error { return jwxjwk.AssignKeyID(key) }

// Key re-exports the jwx JWK key interface, so consumers do not have to
// import jwx directly.
type Key = jwxjwk.Key

// Set re-exports the jwx JWK set interface, so consumers do not have to
// import jwx directly.
type Set = jwxjwk.Set

// Parse parses a JWK or JWKS JSON document into a Set. AKP entries
// (post-quantum ML-DSA keys, draft-ietf-cose-dilithium) are not supported
// by jwx and are decoded by the native AKP parser; sets may mix AKP and
// standard entries. Standard entries remain strictly parsed.
func Parse(data []byte) (Set, error) {
	// Detect the document shape first.
	var probe struct {
		Kty  string            `json:"kty"`
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("unable to parse JWK document: %w", err)
	}

	switch {
	case len(probe.Keys) > 0:
		// JWKS: decode each entry, AKP entries natively.
		set := jwxjwk.NewSet()
		for _, entry := range probe.Keys {
			k, err := parseSingleKey(entry)
			if err != nil {
				return nil, err
			}
			if err := set.AddKey(k); err != nil {
				return nil, fmt.Errorf("unable to add key to set: %w", err)
			}
		}
		return set, nil

	case probe.Kty == akpKty:
		// Single AKP key.
		k, err := ParseMLDSAJWK(data)
		if err != nil {
			return nil, err
		}
		set := jwxjwk.NewSet()
		if err := set.AddKey(k); err != nil {
			return nil, fmt.Errorf("unable to add key to set: %w", err)
		}
		return set, nil

	default:
		// Standard single JWK or JWKS: delegate to jwx (strict).
		return jwxjwk.Parse(data)
	}
}

// parseSingleKey decodes one key entry, routing AKP to the native parser.
func parseSingleKey(entry []byte) (Key, error) {
	var ktyProbe struct {
		Kty string `json:"kty"`
	}
	if err := json.Unmarshal(entry, &ktyProbe); err != nil {
		return nil, fmt.Errorf("unable to parse key entry: %w", err)
	}
	if ktyProbe.Kty == akpKty {
		return ParseMLDSAJWK(entry)
	}
	k, err := jwxjwk.ParseKey(entry)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key entry: %w", err)
	}
	return k, nil
}

// KeySetProviderFunc defines key set provider contract.
type KeySetProviderFunc func(ctx context.Context) (Set, error)

// KeyProviderFunc defines key provider contract.
type KeyProviderFunc func(ctx context.Context) (Key, error)

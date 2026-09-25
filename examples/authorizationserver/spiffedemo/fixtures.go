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

// Package spiffedemo carries the static trust fixtures of the example.org
// SPIFFE trust domain shared by the example authorization server and the
// spiffeclient demo: a fixed JWT-SVID signing key pair whose public part is
// served as the bundle, so the client demo and the server bundle agree
// without external infrastructure.
package spiffedemo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

// TrustDomain is the demo trust domain.
const TrustDomain = "example.org"

// ClientSPIFFEID is the registered demo workload SPIFFE ID.
const ClientSPIFFEID = "spiffe://example.org/my-oauth-client"

// Fixed P-256 scalar of the demo trust-domain JWT-SVID signing key, stable
// so the bundle matches across processes (client demo and example server).
const signingKeyHex = "8da1d0e2f3bc4a5791c0d6b7e5f2a8349c1b6d0e7f3a4528c9b1d6e0f3a4572c"

// JWTSVIDSigningKey materializes the demo trust-domain JWT-SVID signing key
// (ES256, P-256) from the fixed scalar.
func JWTSVIDSigningKey() jwxjwk.Key {
	d, ok := new(big.Int).SetString(signingKeyHex, 16)
	if !ok {
		panic("spiffedemo: invalid signing key hex")
	}
	// The fixed scalar pins the whole key pair (public coordinates included)
	// so the demo bundle matches across processes; the deprecated low-level
	// curve access is the only way to materialize a deterministic P-256 key.
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes()) //nolint:staticcheck // SA1019: deterministic demo fixture requires deriving the public point from the fixed scalar
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, //nolint:staticcheck // SA1019: demo fixture sets the raw coordinates deterministically
		D:         d,                                                   //nolint:staticcheck // SA1019: demo fixture pins the private scalar
	}
	k, err := jwxjwk.Import(priv)
	if err != nil {
		panic(fmt.Errorf("spiffedemo: unable to import signing key: %w", err))
	}
	if err := k.Set("kid", "spiffe-demo-jwt-svid"); err != nil {
		panic(err)
	}
	return k
}

// JWTSVIDPublicKey returns the public part of the demo signing key.
func JWTSVIDPublicKey() jwxjwk.Key {
	pub, err := jwxjwk.PublicKeyOf(JWTSVIDSigningKey())
	if err != nil {
		panic(fmt.Errorf("spiffedemo: unable to derive public key: %w", err))
	}
	return pub
}

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

package hpke

import (
	chpke "crypto/hpke"

	mech "zntr.io/solid/sdk/hpke"
	"zntr.io/solid/sdk/jwk"
)

// kemPublicKey resolves the HPKE encapsulation key of a JWK for the given
// suite, delegated to the mechanism package key conversion (draft section
// 10.1: KEM key pairs are intended for a specific algorithm suite).
func kemPublicKey(k jwk.Key, s *mech.Suite) (chpke.PublicKey, error) {
	return mech.KEMPublicKey(k, s)
}

// kemPrivateKey resolves the HPKE decapsulation key of a JWK for the given
// suite.
func kemPrivateKey(k jwk.Key, s *mech.Suite) (chpke.PrivateKey, error) {
	return mech.KEMPrivateKey(k, s)
}

// verifyKeyUsage rejects keys not explicitly reserved for encryption.
func verifyKeyUsage(k jwk.Key) error {
	return mech.VerifyKeyUsage(k)
}

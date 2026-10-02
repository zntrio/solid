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

package sdtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// saltLengthBytes is the mandatory disclosure salt length: 128 bits
// (RFC 9901 section 9.3, draft-ietf-spice-sd-cwt-08 section 6.1).
const saltLengthBytes = 16

// Digest returns the raw SHA-256 digest over the exact wire bytes of a
// disclosure: the US-ASCII bytes of the base64url string for RFC 9901
// (section 4.2.3), the CBOR bstr bytes for SD-CWT (draft section 3.2).
// Only sha-256 is supported in either spec profile (defensive posture).
func Digest(wire []byte) []byte {
	sum := sha256.Sum256(wire)
	return sum[:]
}

// DigestKey returns the normalized lookup key for a disclosure's wire
// bytes: base64url(sha256(wire)) without padding. Both formats key their
// processing engines on this string; the raw digest bytes only exist on
// the CBOR wire.
func DigestKey(wire []byte) string {
	return base64.RawURLEncoding.EncodeToString(Digest(wire))
}

// NewSalt returns a fresh 128-bit salt from crypto/rand (RFC 9901
// section 9.3, draft-ietf-spice-sd-cwt-08 section 6.1). Issuers wanting
// deterministic salts (tests, RFC vectors) override it via WithSaltFactory.
func NewSalt() ([]byte, error) {
	salt := make([]byte, saltLengthBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

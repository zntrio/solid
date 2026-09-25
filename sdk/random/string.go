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

// Package random provides cryptographically secure random string generation,
// as a standard-library-only replacement for dchest/uniuri.
package random

import (
	cryptorand "crypto/rand"
	"fmt"
)

// StdChars is the default alphanumeric character set.
var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

// String returns a cryptographically secure random string of the given length,
// composed of characters from StdChars.
func String(length int) string {
	return StringChars(length, StdChars)
}

// StringChars returns a cryptographically secure random string of the given
// length, composed of characters from the provided set. Values are drawn with
// rejection sampling to avoid modulo bias.
func StringChars(length int, chars []byte) string {
	if length == 0 {
		return ""
	}
	clen := len(chars)
	if clen < 2 || clen > 256 {
		panic(fmt.Sprintf("random: invalid charset length %d", clen))
	}

	// Largest random byte value usable without modulo bias.
	maxrb := 256 - (256 % clen)

	out := make([]byte, length)
	buf := make([]byte, length)
	i := 0
	for i < length {
		if _, err := cryptorand.Read(buf); err != nil {
			panic(fmt.Sprintf("random: error reading random bytes: %v", err))
		}
		for _, rb := range buf {
			if int(rb) >= maxrb {
				// Skip this value to avoid modulo bias.
				continue
			}
			out[i] = chars[int(rb)%clen]
			i++
			if i == length {
				break
			}
		}
	}
	return string(out)
}

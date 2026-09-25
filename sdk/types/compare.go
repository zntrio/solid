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

package types

import (
	"crypto/subtle"
)

// constantTimeEqInt returns 1 if x == y, 0 otherwise, without branching or
// narrowing conversions. It keeps the constant-time property of the
// comparisons below while staying overflow-safe on the machine word.
func constantTimeEqInt(x, y int) int {
	d := int64(x) - int64(y)
	// d|(-d) is 0 only when d == 0; the arithmetic shift yields 0 then and
	// -1 otherwise, so m+1 is the desired 1/0 selector.
	m := (d | -d) >> 63
	return int(m + 1)
}

// SecureCompare use constant time function to compare the two given array.
func SecureCompare(given, actual []byte) bool {
	if constantTimeEqInt(len(given), len(actual)) == 1 {
		return subtle.ConstantTimeCompare(given, actual) == 1
	}
	// Securely compare actual to itself to keep constant time, but always return false
	if subtle.ConstantTimeCompare(actual, actual) == 1 {
		return false
	}
	return false
}

// SecureCompareString use constant time function to compare the two given string.
func SecureCompareString(given, actual string) bool {
	if constantTimeEqInt(len(given), len(actual)) == 1 {
		return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
	}
	// Securely compare actual to itself to keep constant time, but always return false
	if subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 {
		return false
	}
	return false
}

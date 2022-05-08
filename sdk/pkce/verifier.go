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

package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"zntr.io/solid/sdk/types"
)

const (
	codeVerifierLen = 96
)

// CodeVerifier generates and returns code_verifier and code_challenge.
func CodeVerifier() (string, string, error) {
	// Generate random string
	random := make([]byte, codeVerifierLen)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}

	// Encode verifier
	verifier := base64.RawURLEncoding.EncodeToString(random)

	// Compute and encode challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// No error
	return verifier, challenge, nil
}

// Validate PKCE code verifier against challenge.
func Validate(challenge, verifier string) (bool, error) {
	// Check arguments
	if challenge == "" {
		return false, fmt.Errorf("challenge must not be blank")
	}
	if verifier == "" {
		return false, fmt.Errorf("verifier must not be blank")
	}

	// Decode values
	chRaw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return false, fmt.Errorf("invalid challenge format: %w", err)
	}

	verRaw, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		return false, fmt.Errorf("invalid verifier format: %w", err)
	}

	// Compare values
	same := types.SecureCompare(chRaw, verRaw)

	// No error
	return same, nil
}

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
	"regexp"

	"zntr.io/solid/sdk/types"
)

const (
	codeVerifierLen = 96
)

// codeVerifierFormat validates the RFC 7636 section 4.1 code_verifier syntax:
// 43-128 characters from the unreserved characters set ALPHA / DIGIT / "-" / "." / "_" / "~".
var codeVerifierFormat = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// codeChallengeFormat validates the RFC 7636 section 4.2 "S256" code_challenge
// syntax: the base64url encoding of a 32-octet SHA-256 digest, without padding.
var codeChallengeFormat = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)

// CodeVerifier generates and returns code_verifier and code_challenge.
func CodeVerifier() (verifier, challenge string, err error) {
	// Generate random string
	random := make([]byte, codeVerifierLen)
	if _, errRead := rand.Read(random); errRead != nil {
		return "", "", errRead
	}

	// Encode verifier
	verifier = base64.RawURLEncoding.EncodeToString(random)

	// Compute and encode challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	// No error
	return verifier, challenge, nil
}

// Validate a PKCE code_verifier against a code_challenge as defined by
// RFC 7636 section 4.6: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
// must equal code_challenge. The comparison is constant-time.
func Validate(challenge, verifier string) (bool, error) {
	// Check arguments
	if challenge == "" {
		return false, fmt.Errorf("challenge must not be blank")
	}
	if verifier == "" {
		return false, fmt.Errorf("verifier must not be blank")
	}

	// Validate the code_verifier syntax per RFC 7636 section 4.1.
	if !codeVerifierFormat.MatchString(verifier) {
		return false, fmt.Errorf("invalid verifier format")
	}

	// Validate the code_challenge syntax per RFC 7636 section 4.2 (S256).
	if !codeChallengeFormat.MatchString(challenge) {
		return false, fmt.Errorf("invalid challenge format")
	}

	// Compute the derived challenge: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	// Constant-time comparison of the expected and provided challenges.
	same := types.SecureCompareString(challenge, expected)

	// No error
	return same, nil
}

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
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestCodeVerifier(t *testing.T) {
	verifier, challenge, err := CodeVerifier()
	if err != nil {
		t.Fatalf("CodeVerifier() error = %v", err)
	}
	if !codeVerifierFormat.MatchString(verifier) {
		t.Errorf("CodeVerifier() verifier %q does not match RFC 7636 section 4.1 syntax", verifier)
	}
	if !codeChallengeFormat.MatchString(challenge) {
		t.Errorf("CodeVerifier() challenge %q does not match RFC 7636 section 4.2 S256 syntax", challenge)
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		name      string
		challenge string
		verifier  string
		want      bool
		wantErr   bool
	}{
		{
			name: "Round trip from CodeVerifier",
			want: true,
		},
		{
			name: "Mismatched verifier",
			want: false,
		},
		{
			name:      "Verifier with invalid characters",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			verifier:  "!!!",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "Verifier too short",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "Verifier too long",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			verifier:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "Challenge not valid base64url",
			challenge: "!!!",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "Blank challenge",
			challenge: "",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "Blank verifier",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			verifier:  "",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "Plain method rejected: challenge == verifier bytes",
			challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			want:      false,
		},
		{
			name:      "RFC 7636 Appendix B vector",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			want:      true,
		},
	}

	// Prepare dynamic cases.
	validVerifier, validChallenge, err := CodeVerifier()
	if err != nil {
		t.Fatalf("CodeVerifier() error = %v", err)
	}
	for i := range testCases {
		tc := &testCases[i]
		switch tc.name {
		case "Round trip from CodeVerifier":
			tc.challenge, tc.verifier = validChallenge, validVerifier
		case "Mismatched verifier":
			other, _, err := CodeVerifier()
			if err != nil {
				t.Fatalf("CodeVerifier() error = %v", err)
			}
			tc.challenge, tc.verifier = validChallenge, other
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Validate(tc.challenge, tc.verifier)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestValidateRFC7636Vector recomputes the RFC 7636 Appendix B expected value
// independently, pinning the derivation to BASE64URL-ENCODE(SHA256(verifier)).
func TestValidateRFC7636Vector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	sum := sha256.Sum256([]byte(verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		t.Fatalf("independent derivation mismatch: %s != %s", got, challenge)
	}

	ok, err := Validate(challenge, verifier)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !ok {
		t.Errorf("Validate() = false for the RFC 7636 Appendix B vector")
	}
}

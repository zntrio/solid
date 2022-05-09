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

package pairwise

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	minSaltLength = 16
)

func Hash(salt []byte) Encoder {
	return &hashEncoder{
		salt: salt,
	}
}

// -----------------------------------------------------------------------------

type hashEncoder struct {
	salt []byte
}

func (t *hashEncoder) Encode(sectorID, subject string) (string, error) {
	// Check salt
	if len(t.salt) < minSaltLength {
		return "", errors.New("unable to initialize blake2b hasher, salt too short")
	}

	// Normalize input
	subject = strings.TrimSpace(subject)
	if len(subject) == 0 {
		return "", errors.New("subject can't be blank or empty")
	}

	// Initialize hasher
	h, err := blake2b.New256(t.salt)
	if err != nil {
		return "", fmt.Errorf("unable to initialize blake2b hasher: %w", err)
	}

	// Hash the content
	h.Write([]byte(sectorID))
	h.Write([]byte(subject))

	// Finalize
	sub := h.Sum(nil)

	// Encode hash as Raw Base64 URL
	return base64.RawURLEncoding.EncodeToString(sub[:]), nil
}

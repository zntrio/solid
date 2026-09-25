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

package verifiable

import (
	"crypto/hkdf"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var wrappedUUIDFormat = regexp.MustCompile("^[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59,60}$")

// UUIDGeneratorFunc represents the contract used to feed the wrapper with a
// pre-generated UUID. This is used to pass the UUID byte array coming from your
// favorite generator.
type UUIDGeneratorFunc func() ([16]byte, error)

// StaticUUIDSource is used to set a static UUID byte array content.
func StaticUUIDSource(in [16]byte) UUIDGeneratorFunc {
	return func() ([16]byte, error) {
		return in, nil
	}
}

// UUIDv4Source generates an UUIDv4 based byte array.
func UUIDv4Source() UUIDGeneratorFunc {
	return func() ([16]byte, error) {
		// Generate UUIDv4
		u, err := uuidv4()
		if err != nil {
			return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
		}
		return u, nil
	}
}

// UUIDv7Source generates an UUIDv7 based byte array.
func UUIDv7Source() UUIDGeneratorFunc {
	return func() ([16]byte, error) {
		// Generate UUIDv7
		u, err := uuidv7()
		if err != nil {
			return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv7: %w", err)
		}
		return u, nil
	}
}

// uuidv4 returns a RFC 9562 UUIDv4 as [16]byte, backed by crypto/rand.
func uuidv4() ([16]byte, error) {
	var u [16]byte
	if _, err := cryptorand.Read(u[:]); err != nil {
		return u, fmt.Errorf("unable to read random bytes: %w", err)
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return u, nil
}

// uuidv7 returns a RFC 9562 UUIDv7 (time-ordered) as [16]byte, backed by crypto/rand.
func uuidv7() ([16]byte, error) {
	var u [16]byte
	ms := uint64(time.Now().UnixMilli())
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	if _, err := cryptorand.Read(u[6:]); err != nil {
		return u, fmt.Errorf("unable to read random bytes: %w", err)
	}
	u[6] = (u[6] & 0x0f) | 0x70 // version 7
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return u, nil
}

// -----------------------------------------------------------------------------

// VerifiableUUIDExtractor extends the Verifier to add content extraction helper.
type VerifiableUUIDExtractor interface {
	Verifier
	Extractor[[]byte]
}

// UUIDGenerator wraps the returned UUID byte array from the given source to
// provide additional integrity protection to the content.
//
// The secret key is used to derive a unique secret used to seal the UUID value.
func UUIDGenerator(source UUIDGeneratorFunc, secretKey []byte) Generator {
	return &uuidGenerator{
		randReader: cryptorand.Reader,
		source:     source,
		secretKey:  secretKey,
	}
}

// UUIDVerifier verifies a wrapped UUID signature.
func UUIDVerifier(secretKey []byte) VerifiableUUIDExtractor {
	return &uuidGenerator{
		secretKey: secretKey,
	}
}

// -----------------------------------------------------------------------------

type uuidGenerator struct {
	randReader io.Reader
	secretKey  []byte
	source     UUIDGeneratorFunc
}

func (vu *uuidGenerator) Generate(opts ...GenerateOption) (string, error) {
	// Prepare default settings
	dopts := &generateOption{}
	for _, o := range opts {
		o(dopts)
	}

	// Get an UUID from the source
	uuid, err := vu.source()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve an UUID from the source: %w", err)
	}

	// Generate random nonce (96bits)
	var nonce [12]byte
	if _, errNonce := io.ReadFull(vu.randReader, nonce[:]); errNonce != nil {
		return "", fmt.Errorf("unable to generate random nonce: %w", errNonce)
	}

	// Prepare token prefix
	prefix := ""
	if dopts.prefix != "" {
		// Ensure prefix syntax
		if nonAuthorizedChars.MatchString(dopts.prefix) {
			return "", fmt.Errorf("the given prefix %q contains forbidden characters, (0-9a-z-) are allowed", dopts.prefix)
		}
		prefix = dopts.prefix + defaultSeparator
	}

	// Derive a signature key to prevent direct secret key usages which could
	// threaten all generated tokens in the potential case of a secret leak.
	var authKey [32]byte
	derivedKey, err := hkdf.Key(sha256.New, vu.secretKey, nonce[:], "solid-uuid-wrapper-mac-v1", 32)
	if err != nil {
		return "", fmt.Errorf("unable to derive authentication key: %w", err)
	}
	copy(authKey[:], derivedKey)

	// Prepare protected
	protected := []byte("solid-uuid-protected-token-v1")
	protected = append(protected, []byte(prefix)...)
	protected = append(protected, uuid[:]...)

	// Prepare HMAC
	hm := hmac.New(sha256.New, authKey[:])
	hm.Write(protected)

	return prefix + toPaddedBase62(uuid[:], 22) + "_" + toPaddedBase62(hm.Sum(nonce[:]), 59), nil
}

func (vu *uuidGenerator) Verify(in string) error {
	_, err := vu.Extract(in)
	return err
}

func (vu *uuidGenerator) Extract(in string) ([]byte, error) {
	// Detect prefix usage
	var prefix string
	if parts := strings.SplitN(in, defaultSeparator, 3); len(parts) == 3 {
		prefix = parts[0] + defaultSeparator
		in = parts[1] + defaultSeparator + parts[2]
	}

	// Ensure a valid token format
	if !wrappedUUIDFormat.MatchString(in) {
		return nil, errors.New("invalid token format")
	}

	// Split token
	parts := strings.SplitN(in, "_", 2)

	// Decode UUID
	uuid, err := parsePaddedBase62(parts[0], 16)
	if err != nil {
		return nil, errors.New("invalid token syntax")
	}

	// Decode Nonce || Signature
	sig, err := parsePaddedBase62(parts[1], 44)
	if err != nil {
		return nil, errors.New("invalid token syntax")
	}

	// Derive a signature key to prevent direct secret key usages which could
	// threaten all generated tokens in the potential case of a secret leak.
	var authKey [32]byte
	derivedKey, err := hkdf.Key(sha256.New, vu.secretKey, sig[:12], "solid-uuid-wrapper-mac-v1", 32)
	if err != nil {
		return nil, fmt.Errorf("unable to derive authentication key: %w", err)
	}
	copy(authKey[:], derivedKey)

	// Prepare protected
	protected := []byte("solid-uuid-protected-token-v1")
	protected = append(protected, []byte(prefix)...)
	protected = append(protected, uuid[:]...)

	// Prepare HMAC
	hm := hmac.New(sha256.New, authKey[:])
	hm.Write(protected)

	// Compare signature
	if subtle.ConstantTimeCompare(sig[12:], hm.Sum(nil)) != 1 {
		return nil, ErrTokenNotAuthenticated
	}

	return uuid, nil
}

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

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/url"
	"time"

	"github.com/dchest/uniuri"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
)

// Prover describes prover contract
type Prover interface {
	Prove(htm string, htu *url.URL) (string, error)
}

// -----------------------------------------------------------------------------

// DefaultProver returns a prover instance with a generated key.
func DefaultProver() (Prover, error) {
	// Generate an ephemeral key
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate P-256 private key: %w", err)
	}

	// Delegate to other constructor
	return KeyProver(jose.SigningKey{
		Algorithm: jose.ES256,
		Key: &jose.JSONWebKey{
			Use:   "sig",
			Key:   pk,
			KeyID: uniuri.NewLen(8),
		},
	})
}

// KeyProver uses the given key to instanciate a prover.
func KeyProver(k jose.SigningKey) (Prover, error) {
	// Build instance
	return &defaultProver{
		privateKey: k,
	}, nil
}

// -----------------------------------------------------------------------------

type defaultProver struct {
	privateKey jose.SigningKey
}

func (p *defaultProver) Prove(htm string, htu *url.URL) (string, error) {
	// Check parameters
	if htm == "" {
		return "", fmt.Errorf("htm must not be blank")
	}
	if htu == nil {
		return "", fmt.Errorf("htu must not be nil")
	}

	// Create proof claims
	claims := &proofClaims{
		JTI:        uniuri.NewLen(16),
		HTTPMethod: htm,
		HTTPURL:    fmt.Sprintf("%s://%s%s", htu.Scheme, htu.Host, htu.Path),
		IssuedAt:   uint64(time.Now().UTC().Unix()),
	}

	// Prepare signer options
	options := (&jose.SignerOptions{}).WithType("dpop+jwt")
	options.EmbedJWK = true

	// Prepare a signer
	sig, err := jose.NewSigner(p.privateKey, options)
	if err != nil {
		return "", fmt.Errorf("unable to prepare signer: %w", err)
	}

	// Generate the final proof
	raw, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to generate DPoP: %w", err)
	}

	// Return proof
	return raw, nil
}

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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dchest/uniuri"

	"zntr.io/solid/pkg/sdk/jwt"
	"zntr.io/solid/pkg/sdk/types"
)

// -----------------------------------------------------------------------------

// DefaultProver uses the given signer to generate a DPoP Proof.
func DefaultProver(signer jwt.Signer) (Prover, error) {
	// Check arguments
	if types.IsNil(signer) {
		return nil, errors.New("unable to instantiate a DPoP Prover with nil signer")
	}

	// Build instance
	return &defaultProver{
		signer: signer,
	}, nil
}

// -----------------------------------------------------------------------------

type defaultProver struct {
	signer jwt.Signer
}

func (p *defaultProver) Prove(htm, htu string) (string, error) {
	// Check parameters
	if htm == "" {
		return "", fmt.Errorf("htm must not be blank")
	}
	if htu == "" {
		return "", fmt.Errorf("htu must not be blank")
	}

	// Validate url
	u, err := url.ParseRequestURI(htu)
	if err != nil {
		return "", fmt.Errorf("invalid URL syntax for proof '%s': %w", htu, err)
	}

	// Validate method
	switch strings.ToUpper(htm) {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions:
	case http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
	default:
		return "", fmt.Errorf("invalid HTTP Method in proof '%s'", htm)
	}

	// Create proof claims
	claims := &proofClaims{
		JTI:        uniuri.NewLen(JTICodeLength),
		HTTPMethod: htm,
		HTTPURL:    fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path),
		IssuedAt:   uint64(time.Now().UTC().Unix()),
	}

	// Sign claims
	proof, err := p.signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("unable to generate DPoP proof: %w", err)
	}

	// Return proof
	return proof, nil
}

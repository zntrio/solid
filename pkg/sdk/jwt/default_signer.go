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

package jwt

import (
	"errors"
	"fmt"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"zntr.io/solid/pkg/sdk/types"
)

// DefaultSigner declare a default JWT signer.
func DefaultSigner(privateKey jose.SigningKey, opts *jose.SignerOptions) Signer {
	return &defaultSigner{
		privateKey: privateKey,
		options:    opts,
	}
}

// -----------------------------------------------------------------------------

type defaultSigner struct {
	privateKey jose.SigningKey
	options    *jose.SignerOptions
}

func (ds *defaultSigner) Sign(claims interface{}) (string, error) {
	// Check arguments
	if types.IsNil(claims) {
		return "", errors.New("unable to sign nil claim object")
	}

	// Prepare a signer
	sig, err := jose.NewSigner(ds.privateKey, ds.options)
	if err != nil {
		return "", fmt.Errorf("unable to prepare signer: %w", err)
	}

	// Generate the final proof
	raw, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to generate JWT: %w", err)
	}

	// No error
	return raw, nil
}

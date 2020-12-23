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

package paseto

import (
	"encoding/json"
	"errors"
	"fmt"

	pasetolib "github.com/o1egl/paseto"
	"github.com/square/go-jose/v3"

	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/sdk/types"
)

// DefaultSigner declare a default JWT signer.
func DefaultSigner(privateKey *jose.JSONWebKey) token.Signer {
	return &defaultSigner{
		privateKey: privateKey,
	}
}

// -----------------------------------------------------------------------------

type defaultSigner struct {
	privateKey *jose.JSONWebKey
}

func (ds *defaultSigner) Sign(claims interface{}) (string, error) {
	// Check arguments
	if types.IsNil(claims) {
		return "", errors.New("unable to sign nil claim object")
	}

	// Prepare footer
	footerJSON := map[string]string{
		"kid": ds.privateKey.KeyID,
	}
	footer, err := json.Marshal(footerJSON)
	if err != nil {
		return "", fmt.Errorf("unable to encode paseto footer: %w", err)
	}

	// Prepare a signer
	raw, err := pasetolib.NewV2().Sign(ds.privateKey.Key, claims, string(footer))
	if err != nil {
		return "", fmt.Errorf("unable to sign paseto token: %w", err)
	}

	// No error
	return raw, nil
}

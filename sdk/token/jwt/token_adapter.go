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
	"crypto"
	"encoding/base64"
	"fmt"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

type tokenAdapter struct {
	token *josejwt.JSONWebToken
}

func (tw *tokenAdapter) Type() (string, error) {
	if len(tw.token.Headers) == 0 {
		return "", fmt.Errorf("unable to retrieve header")
	}

	if typ, ok := tw.token.Headers[0].ExtraHeaders["typ"]; ok {
		return fmt.Sprintf("%v", typ), nil
	}

	return "", fmt.Errorf("unable to retrieve token type")
}

func (tw *tokenAdapter) KeyID() (string, error) {
	if len(tw.token.Headers) == 0 {
		return "", fmt.Errorf("unable to retrieve kid claim from header")
	}
	return tw.token.Headers[0].KeyID, nil
}

func (tw *tokenAdapter) PublicKey() (any, error) {
	if len(tw.token.Headers) == 0 {
		return "", fmt.Errorf("unable to retrieve embededded jwk from header")
	}
	return tw.token.Headers[0].JSONWebKey, nil
}

func (tw *tokenAdapter) PublicKeyThumbPrint() (string, error) {
	if len(tw.token.Headers) == 0 {
		return "", fmt.Errorf("unable to retrieve embededded jwk from header")
	}

	// Generate thumbprint
	h, err := tw.token.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("unable to generate embedded jwk thumbprint: %w", err)
	}

	// No error
	return base64.RawURLEncoding.EncodeToString(h), nil
}

func (tw *tokenAdapter) Algorithm() (string, error) {
	if len(tw.token.Headers) == 0 {
		return "", fmt.Errorf("unable to retrieve `alg` claim from header")
	}
	return tw.token.Headers[0].Algorithm, nil
}

func (tw *tokenAdapter) Claims(publicKey any, claims any) error {
	return tw.token.Claims(publicKey, claims)
}

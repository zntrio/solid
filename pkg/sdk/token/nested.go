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

package token

import (
	"context"
	"fmt"

	"zntr.io/solid/pkg/sdk/types"
)

// Encryption decorration for token serializer.
func Encryption(serializer Serializer, encrypter Encrypter) Serializer {
	return &tokenEncrypter{
		serializer: serializer,
		encrypter:  encrypter,
	}
}

// -----------------------------------------------------------------------------

type tokenEncrypter struct {
	serializer Serializer
	encrypter  Encrypter
}

func (tw *tokenEncrypter) Serialize(ctx context.Context, claims interface{}) (string, error) {
	// Check arguments
	if types.IsNil(tw.serializer) {
		return "", fmt.Errorf("unable to proceed with nil signer")
	}
	if types.IsNil(tw.encrypter) {
		return "", fmt.Errorf("unable to proceed with nil signer")
	}

	// Sign token first
	signed, err := tw.serializer.Serialize(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to prepare signed token for encryption: %w", err)
	}

	// Encrypt token
	encrypted, err := tw.encrypter.Encrypt(ctx, tw.serializer.ContentType(), signed, []byte(`urn:solid:token:sign-and-encrypt`))
	if err != nil {
		return "", fmt.Errorf("unable to encrypt signed token: %w", err)
	}

	// No error
	return encrypted, nil
}

func (tw *tokenEncrypter) ContentType() string {
	return "HYBRID"
}

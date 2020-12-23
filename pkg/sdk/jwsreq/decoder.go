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

package jwsreq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/token"
)

// -----------------------------------------------------------------------------

// AuthorizationRequestDecoder returns an authorization request decoder instance.
func AuthorizationRequestDecoder(verifier token.Verifier) AuthorizationDecoder {
	return &tokenDecoder{
		verifier: verifier,
	}
}

type tokenDecoder struct {
	verifier token.Verifier
}

func (d *tokenDecoder) Decode(ctx context.Context, value string) (*corev1.AuthorizationRequest, error) {
	// Check arguments
	if value == "" {
		return nil, fmt.Errorf("value must not be blank")
	}

	// Extract claims
	var claims map[string]interface{}
	if err := d.verifier.Claims(value, &claims); err != nil {
		return nil, fmt.Errorf("unable to decode request claims: %w", err)
	}

	// Re-encode to json
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(claims); err != nil {
		return nil, fmt.Errorf("unable to reencode request claims as json : %w", err)
	}

	// Verify token claims
	var req corev1.AuthorizationRequest
	if err := protojson.Unmarshal(buf.Bytes(), &req); err != nil {
		return nil, fmt.Errorf("unable to decode request payload: %w", err)
	}

	// No error
	return &req, nil
}

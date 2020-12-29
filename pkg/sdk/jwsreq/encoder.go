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
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/token"
)

// -----------------------------------------------------------------------------

// AuthorizationRequestEncoder returns an authorization request encoder instance.
func AuthorizationRequestEncoder(signer token.Signer) AuthorizationEncoder {
	return &tokenEncoder{
		signer: signer,
	}
}

type tokenEncoder struct {
	signer token.Signer
}

func (enc *tokenEncoder) Encode(ctx context.Context, ar *corev1.AuthorizationRequest) (string, error) {
	// Check arguments
	if ar == nil {
		return "", fmt.Errorf("unable to encode nil request")
	}

	// Encode ar as json
	jsonString, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}.Marshal(ar)
	if err != nil {
		return "", fmt.Errorf("unable to prepare request: %w", err)
	}

	// Decode using json
	var claims map[string]interface{}
	if err = json.Unmarshal(jsonString, &claims); err != nil {
		return "", fmt.Errorf("unable to serialize request payload: %w", err)
	}

	// Sign request
	req, err := enc.signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign request: %w", err)
	}

	// No error
	return req, nil
}

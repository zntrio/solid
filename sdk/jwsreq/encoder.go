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

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/token"
)

// -----------------------------------------------------------------------------

// AuthorizationRequestEncoder returns an authorization request encoder instance.
func AuthorizationRequestEncoder(signer token.Signer) AuthorizationEncoder {
	return &tokenEncoder{
		signer: signer,
	}
}

// AuthorizationRequestEncoderWithOptions returns an authorization request
// encoder that merges the given envelope claims into every serialized
// request object. The envelope carries the JOSE claims with no
// AuthorizationRequest representation (iss, aud, exp, iat, nbf, jti) plus
// any protocol claims without a proto field (e.g. the CIBA binding_message
// and requested_expiry of OpenID CIBA Core 1.0 section 7.1.1); injected
// values win over payload-derived ones. The decoder strips the envelope
// claims it validates (see stripEnvelopeClaims), so an encode/decode
// round-trip returns the proto-representable request.
func AuthorizationRequestEncoderWithOptions(signer token.Signer, envelope map[string]any) AuthorizationEncoder {
	return &tokenEncoder{
		signer:   signer,
		envelope: envelope,
	}
}

type tokenEncoder struct {
	signer   token.Signer
	envelope map[string]any
}

func (enc *tokenEncoder) Encode(ctx context.Context, ar *flowv1.AuthorizationRequest) (string, error) {
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
	var claims map[string]any
	if err = json.Unmarshal(jsonString, &claims); err != nil {
		return "", fmt.Errorf("unable to serialize request payload: %w", err)
	}

	// Merge the envelope claims: injected values win (they are the JOSE
	// envelope and the claims without a proto representation).
	for k, v := range enc.envelope {
		claims[k] = v
	}

	// Sign request
	req, err := enc.signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign request: %w", err)
	}

	// No error
	return req, nil
}

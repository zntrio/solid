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

package jarm

import (
	"context"
	"fmt"
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/token"
)

// -----------------------------------------------------------------------------

// Encoder builds a Response Mode encoder instance.
func Encoder(signer token.Signer) ResponseEncoder {
	return &tokenEncoder{
		signer: signer,
	}
}

type tokenEncoder struct {
	signer token.Signer
}

func (d *tokenEncoder) Encode(ctx context.Context, issuer string, resp *corev1.AuthorizationCodeResponse) (string, error) {
	// Check arguments
	if issuer == "" {
		return "", fmt.Errorf("unable to process empty issuer")
	}
	if resp == nil {
		return "", fmt.Errorf("unable to process nil response")
	}

	// Prepare response claims
	var claims *responseClaims
	if resp.Error != nil {
		claims = &responseClaims{
			State:            resp.State,
			Error:            resp.Error.Err,
			ErrorDescription: resp.Error.ErrorDescription,
		}
	} else {
		// Validate mandatory fields
		if resp.ClientId == "" {
			return "", fmt.Errorf("client_id must not be blank")
		}
		if resp.Code == "" {
			return "", fmt.Errorf("code must not be blank")
		}
		if resp.State == "" {
			return "", fmt.Errorf("state must not be blank")
		}
		if resp.ExpiresIn <= 0 {
			return "", fmt.Errorf("expires_in must not be strictly positive")
		}

		claims = &responseClaims{
			State:     resp.State,
			Issuer:    resp.Issuer,
			Audience:  resp.ClientId,
			Code:      resp.Code,
			ExpiresAt: uint64(time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second).Unix()),
		}
	}

	// Sign the claims to generate token
	raw, err := d.signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("unable to encode JARM assertion: %w", err)
	}

	// No error
	return raw, nil
}

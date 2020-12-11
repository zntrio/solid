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
	"zntr.io/solid/pkg/sdk/jwt"
)

// -----------------------------------------------------------------------------

// JWTEncoder builds a JWT Response encoder instance.
func JWTEncoder(signer jwt.Signer) ResponseEncoder {
	return &jwtEncoder{
		signer: signer,
	}
}

type jwtEncoder struct {
	signer jwt.Signer
}

func (d *jwtEncoder) Encode(ctx context.Context, issuer string, resp *corev1.AuthorizationCodeResponse) (string, error) {
	// Check arguments
	if issuer == "" {
		return "", fmt.Errorf("unable to process empty issuer")
	}
<<<<<<< HEAD
	if resp == nil {
		return "", fmt.Errorf("unable to process nil response")
=======
	if issuer != resp.Issuer {
		return "", fmt.Errorf("unbale to validate issuer match, reponse and given issuer don't match")
	}

	// Retrieve key from provider
	k, err := d.keyProvider(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve signing key from provider: %w", err)
	}
	if k == nil {
		return "", fmt.Errorf("key provider returned nil key")
	}
	if k.IsPublic() {
		return "", fmt.Errorf("key provider returned a public key")
>>>>>>> 9876833 (feat(oidc): iss authorization code response.)
	}

	// Prepare response claims
	var claims *jwtResponseClaims
	if resp.Error != nil {
		claims = &jwtResponseClaims{
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

		claims = &jwtResponseClaims{
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

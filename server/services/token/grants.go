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
	"fmt"
	"net/url"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
)

// validateGrantPreamble applies the validation steps shared by every token
// grant handler: client and request nullity, issuer syntax, and the client
// capability check for the given grant type. When it fails it returns both
// the protocol error to assign to the response and its cause; on success
// both returns are nil and the handler proceeds with grant-specific logic.
func validateGrantPreamble(client *clientv1.Client, req *flowv1.TokenRequest, grantType string) (*corev1.Error, error) {
	// Check parameters
	if client == nil {
		err := rfcerrors.ServerError().Build()
		return err, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		err := rfcerrors.ServerError().Build()
		return err, fmt.Errorf("unable to process with nil request")
	}

	// Check issuer syntax (RFC 6749 section 5.2: malformed client input is
	// an invalid_request, not a server fault).
	if req.Issuer == "" {
		err := rfcerrors.InvalidRequest().Build()
		return err, fmt.Errorf("issuer must not be blank")
	}
	if _, err := url.ParseRequestURI(req.Issuer); err != nil {
		errRes := rfcerrors.InvalidRequest().Build()
		return errRes, fmt.Errorf("issuer must be a valid url: %w", err)
	}

	// Validate client capabilities: the client is authenticated but has no
	// registration for this grant type (RFC 6749 section 5.2:
	// unauthorized_client).
	if !types.StringArray(client.GrantTypes).Contains(grantType) {
		err := rfcerrors.UnauthorizedClient().Build()
		return err, fmt.Errorf("client is not authorized to use grant type '%s'", grantType)
	}
	return nil, nil
}

// isUnreservedChar reports whether the rune belongs to the unreserved set
// defined by RFC 3986 section 2.3: ALPHA / DIGIT / "-" / "." / "_" / "~".
// RFC 7636 section 4.1 restricts code verifiers and challenges to this set.
func isUnreservedChar(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-' || r == '.' || r == '_' || r == '~':
		return true
	default:
		return false
	}
}

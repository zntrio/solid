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

package authorization

import (
	"context"

	"go.zenithar.org/solid/pkg/rfcerrors"

	"github.com/golang/protobuf/ptypes/wrappers"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

// ValidateAuthorization validates authorization request.
func ValidateAuthorization(ctx context.Context, req *corev1.AuthorizationRequest) *corev1.Error {
	// Check req nullity
	if req == nil {
		return &corev1.Error{
			Err: "invalid_request",
			ErrorDescription: &wrappers.StringValue{
				Value: "request is nil",
			},
		}
	}

	// Validate request attributes
	if req.State == "" {
		return rfcerrors.InvalidRequest("<missing>")
	}

	if req.Scope == "" || req.ResponseType == "" || req.ClientId == "" || req.RedirectUri == "" || req.CodeChallenge == "" || req.CodeChallengeMethod == "" {
		return rfcerrors.InvalidRequest(req.State)
	}

	if req.CodeChallengeMethod != "S256" {
		return rfcerrors.InvalidRequest(req.State)
	}

	// Return result
	return nil
}

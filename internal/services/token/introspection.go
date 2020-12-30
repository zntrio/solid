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
	"errors"
	"fmt"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/storage"
)

func (s *service) Introspect(ctx context.Context, req *corev1.TokenIntrospectionRequest) (*corev1.TokenIntrospectionResponse, error) {
	res := &corev1.TokenIntrospectionResponse{}

	// Check parameters
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("could not process nil request")
	}
	if req.Client == nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("no client authentication found")
	}
	if req.Token == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("token parameter is mandatory")
	}

	// Retrieve client information
	_, err := s.clients.Get(ctx, req.Client.ClientId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidClient().Build()
		}
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Retrieve token by value
	t, err := s.tokens.GetByValue(ctx, req.Token)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to retrieve to token: %w", err)
	}
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		res.Token = &corev1.Token{
			Value:  req.Token,
			Status: corev1.TokenStatus_TOKEN_STATUS_INVALID,
		}
		return res, nil
	}

	// Return the token
	res.Token = t

	// No error
	return res, nil
}

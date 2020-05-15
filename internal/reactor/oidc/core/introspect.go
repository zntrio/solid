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

package core

import (
	"context"
	"fmt"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/reactor"
	"go.zenithar.org/solid/pkg/types"
)

// IntrospectionHandler handles introspection requests.
var IntrospectionHandler = func(token services.Token) reactor.HandlerFunc {
	return func(ctx context.Context, r interface{}) (interface{}, error) {
		// Check nil request
		if types.IsNil(r) {
			return nil, fmt.Errorf("unable to process nil request")
		}

		// Check request type
		req, ok := r.(*corev1.TokenIntrospectionRequest)
		if !ok {
			return nil, fmt.Errorf("invalid request type %T", req)
		}

		// Delegate to service
		return token.Introspect(ctx, req)
	}
}

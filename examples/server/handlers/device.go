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

package handlers

import (
	"net/http"

	"zntr.io/solid/examples/server/middleware"
	"zntr.io/solid/pkg/server/authorizationserver"
	"zntr.io/solid/pkg/sdk/rfcerrors"
)

// Device handle device code validation.
func Device(as authorizationserver.AuthorizationServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Retrieve subject form context
		sub, ok := middleware.Subject(ctx)
		if !ok || sub == "" {
			withError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
			return
		}
	})
}

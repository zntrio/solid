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

	"zntr.io/solid/pkg/jwk"
	"zntr.io/solid/pkg/rfcerrors"

	"zntr.io/solid/pkg/authorizationserver"
)

// JWKS handle OIDC Discovery HTTP for JWKS.
func JWKS(as authorizationserver.AuthorizationServer, keySetProvider jwk.KeySetProviderFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the active keyset
		ks, err := keySetProvider(r.Context())
		if err != nil {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}

		// Send the JWKS
		withJSON(w, r, http.StatusOK, ks)
	})
}

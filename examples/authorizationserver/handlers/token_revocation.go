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
	"log"
	"net/http"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
)

// TokenRevocation handles token revocation HTTP requests.
func TokenRevocation(issuer string, tokenz services.Token) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		var (
			ctx           = r.Context()
			token         = r.FormValue("token")
			tokenTypeHint = r.FormValue("token_type_hint")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Send request to reactor
		res, err := tokenz.Revoke(ctx, &tokenv1.RevokeRequest{
			Issuer:        issuer,
			Client:        client,
			Token:         token,
			TokenTypeHint: optionalString(tokenTypeHint),
		})
		if err != nil {
			log.Println("unable to process revocation request: %w", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}
	})
}

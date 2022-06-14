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

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
)

// TokenIntrospection handles token introspection HTTP requests.
func TokenIntrospection(issuer string, tokenz services.Token) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		var (
			ctx              = r.Context()
			tokenRaw         = r.FormValue("token")
			tokenTypeHintRaw = r.FormValue("token_type_hint")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Prepare msg
		msg := &corev1.TokenIntrospectionRequest{
			Issuer:        issuer,
			Client:        client,
			Token:         tokenRaw,
			TokenTypeHint: optionalString(tokenTypeHintRaw),
		}

		// Send request to reactor
		res, err := tokenz.Introspect(ctx, msg)
		if err != nil {
			log.Println("unable to process introspection request: %w", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		active := (res.Token.Status == corev1.TokenStatus_TOKEN_STATUS_ACTIVE) && token.IsUsable(res.Token)
		resp := map[string]interface{}{
			"active": active,
		}
		if active {
			resp["scope"] = res.Token.Metadata.Scope
			resp["client_id"] = res.Token.Metadata.ClientId
			resp["exp"] = res.Token.Metadata.ExpiresAt
			resp["iat"] = res.Token.Metadata.IssuedAt
			resp["nbf"] = res.Token.Metadata.NotBefore
			resp["sub"] = res.Token.Metadata.Subject
			resp["aud"] = res.Token.Metadata.Audience
			resp["iss"] = res.Token.Metadata.Issuer
			resp["jti"] = res.Token.TokenId

			// Add confirmation
			if res.Token.Confirmation != nil {
				resp["token_type"] = "DPoP"
				resp["cnf"] = res.Token.Confirmation
			} else {
				resp["token_type"] = "Bearer"
			}
		}

		// Send json reponse
		respond.WithJSON(w, r, http.StatusOK, resp)
	})
}

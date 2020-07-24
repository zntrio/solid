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

	"github.com/golang/protobuf/ptypes/wrappers"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/server/authorizationserver"
	"zntr.io/solid/pkg/server/clientauthentication"
	"zntr.io/solid/pkg/sdk/rfcerrors"
)

// TokenIntrospection handles token introspection HTTP requests.
func TokenIntrospection(as authorizationserver.AuthorizationServer) http.Handler {
	type response struct {
		Active bool `json:"active"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			q             = r.URL.Query()
			ctx           = r.Context()
			token         = q.Get("token")
			tokenTypeHint = q.Get("token_type_hint")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			withError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient(""))
			return
		}

		// Prepare msg
		msg := &corev1.TokenIntrospectionRequest{
			Client: client,
			Token:  token,
		}
		if tokenTypeHint != "" {
			msg.TokenTypeHint = &wrappers.StringValue{
				Value: tokenTypeHint,
			}
		}

		// Send request to reactor
		res, err := as.Do(ctx, msg)
		introRes, ok := res.(*corev1.TokenIntrospectionResponse)
		if !ok {
			withJSON(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to process introspection request: %w", err)
			withError(w, r, http.StatusBadRequest, introRes.Error)
			return
		}

		// Send json reponse
		withJSON(w, r, http.StatusOK, &response{
			Active: introRes.Token.Status == corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
		})
	})
}

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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/authorizationserver"
	"go.zenithar.org/solid/pkg/clientauthentication"
	"go.zenithar.org/solid/pkg/rfcerrors"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// TokenRevocation handles token revocation HTTP requests.
func TokenRevocation(as authorizationserver.AuthorizationServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx           = r.Context()
			q             = r.URL.Query()
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
		msg := &corev1.TokenRevocationRequest{
			Client: client,
			Token:  token,
		}
		if tokenTypeHint != "" {
			msg.TokenTypeHint = &wrappers.StringValue{
				Value: tokenTypeHint,
			}
		}

		// Send request to reactor
		res, err := as.Do(r.Context(), msg)
		revoRes, ok := res.(*corev1.TokenRevocationResponse)
		if !ok {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to process revocation request: %w", err)
			withError(w, r, http.StatusBadRequest, revoRes.Error)
			return
		}
	})
}

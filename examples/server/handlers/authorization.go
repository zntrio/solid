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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/square/go-jose/v3"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/examples/server/middleware"
	"zntr.io/solid/pkg/sdk/jarm"
	"zntr.io/solid/pkg/sdk/jwsreq"
	"zntr.io/solid/pkg/sdk/jwt"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/authorizationserver"
	"zntr.io/solid/pkg/server/storage"
)

// Authorization handles authorization HTTP requests.
func Authorization(as authorizationserver.AuthorizationServer, clients storage.ClientReader, requestDecoder jwsreq.AuthorizationDecoder, jarmEncoder jarm.ResponseEncoder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only GET verb
		if r.Method != http.MethodGet {
			withError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Parameters
		var (
			ctx        = r.Context()
			q          = r.URL.Query()
			clientID   = q.Get("client_id")
			requestRaw = q.Get("request")
		)

		// Retrieve subject form context
		sub, ok := middleware.Subject(ctx)
		if !ok || sub == "" {
			withError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
			return
		}

		// Retrieve client
		client, err := clients.Get(ctx, clientID)
		if err != nil {
			withError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Prepare client request decoder
		clientRequestDecoder := jwsreq.JWTAuthorizationDecoder(jwt.DefaultVerifier(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
			var jwks jose.JSONWebKeySet
			if err := json.Unmarshal(client.Jwks, &jwks); err != nil {
				return nil, fmt.Errorf("unable to decode client JWKS")
			}

			// No error
			return &jwks, nil
		}, []string{"ES384"}))

		// Decode request
		ar, err := clientRequestDecoder.Decode(ctx, requestRaw)
		if err != nil {
			log.Println("unable to decode request:", err)
			withError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Send request to reactor
		res, err := as.Do(ctx, &corev1.AuthorizationCodeRequest{
			Subject:              sub,
			AuthorizationRequest: ar,
		})
		authRes, ok := res.(*corev1.AuthorizationCodeResponse)
		if !ok {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}
		if err != nil {
			log.Println("unable to process authorization request:", err)
			withError(w, r, http.StatusBadRequest, authRes.Error)
			return
		}

		// Build redirection uri
		u, err := url.ParseRequestURI(authRes.RedirectUri)
		if err != nil {
			log.Println("unable to process redirect uri:", err)
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}

		// Encode JARM
		jarmToken, err := jarmEncoder.Encode(ctx, as.Issuer().String(), authRes)
		if err != nil {
			log.Println("unable to produce JARM token:", err)
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}

		// Assemble final uri
		params := url.Values{}
		params.Set("response", jarmToken)

		// Assign new params
		u.RawQuery = params.Encode()

		// Redirect to application
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
}

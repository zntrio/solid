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
	"encoding/json"
	"log"
	"net/http"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/authorizationserver"
	"go.zenithar.org/solid/pkg/clientauthentication"
	"go.zenithar.org/solid/pkg/rfcerrors"
)

// PushedAuthorizationRequest handles PAR HTTP requests.
func PushedAuthorizationRequest(as authorizationserver.AuthorizationServer) http.Handler {
	type response struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  uint64 `json:"expires_in"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		}

		var (
			ctx                 = r.Context()
			q                   = r.URL.Query()
			audience            = q.Get("audience")
			state               = q.Get("state")
			clientID            = q.Get("client_id")
			scope               = q.Get("scope")
			redirectURI         = q.Get("redirect_uri")
			responseType        = q.Get("response_type")
			codeChallenge       = q.Get("code_challenge")
			codeChallengeMethod = q.Get("code_challenge_method")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			json.NewEncoder(w).Encode(rfcerrors.InvalidClient(""))
			return
		}

		// Send request to reactor
		res, err := as.Do(ctx, &corev1.RegistrationRequest{
			Client: client,
			Request: &corev1.AuthorizationRequest{
				Audience:            audience,
				State:               state,
				ClientId:            clientID,
				Scope:               scope,
				RedirectUri:         redirectURI,
				ResponseType:        responseType,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
			},
		})
		parRes, ok := res.(*corev1.RegistrationResponse)
		if !ok {
			withJSON(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to register authorization request:", err)
			withJSON(w, r, http.StatusBadRequest, parRes.Error)
			return
		}

		// Send json response
		withJSON(w, r, http.StatusCreated, &response{
			RequestURI: parRes.RequestUri,
			ExpiresIn:  parRes.ExpiresIn,
		})
	})
}

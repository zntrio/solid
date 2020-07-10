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

	"github.com/square/go-jose/v3"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/dpop"
	"zntr.io/solid/pkg/sdk/jwsreq"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/authorizationserver"
	"zntr.io/solid/pkg/server/clientauthentication"
)

// PushedAuthorizationRequest handles PAR HTTP requests.
func PushedAuthorizationRequest(as authorizationserver.AuthorizationServer, dpopVerifier dpop.Verifier) http.Handler {
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
			ctx        = r.Context()
			q          = r.URL.Query()
			dpopProof  = r.Header.Get("DPoP")
			requestRaw = q.Get("request")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			json.NewEncoder(w).Encode(rfcerrors.InvalidClient(""))
			return
		}

		// Check dpop proof
		jkt, err := dpopVerifier.Verify(ctx, r, dpopProof)
		if err != nil {
			log.Println("unable to validate dpop proof:", err)
			withError(w, r, http.StatusBadRequest, rfcerrors.InvalidDPoPProof())
			return
		}

		// Prepare client request decoder
		clientRequestDecoder := jwsreq.JWTAuthorizationDecoder(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
			var jwks jose.JSONWebKeySet
			if err := json.Unmarshal(client.Jwks, &jwks); err != nil {
				return nil, fmt.Errorf("unable to decode client JWKS")
			}

			// No error
			return &jwks, nil
		})

		// Decode request
		ar, err := clientRequestDecoder.Decode(ctx, requestRaw)
		if err != nil {
			log.Println("unable to decode request:", err)
			withError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest(""))
			return
		}

		// Send request to reactor
		res, err := as.Do(ctx, &corev1.RegistrationRequest{
			Client:               client,
			AuthorizationRequest: ar,
			Confirmation: &corev1.TokenConfirmation{
				Jkt: jkt,
			},
		})
		parRes, ok := res.(*corev1.RegistrationResponse)
		if !ok {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to register authorization request:", err)
			withError(w, r, http.StatusBadRequest, parRes.Error)
			return
		}

		// Send json response
		withJSON(w, r, http.StatusCreated, &response{
			RequestURI: parRes.RequestUri,
			ExpiresIn:  parRes.ExpiresIn,
		})
	})
}

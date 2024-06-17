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

	"github.com/go-jose/go-jose/v4"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jwsreq"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
)

// PushedAuthorizationRequest handles PAR HTTP requests.
func PushedAuthorizationRequest(issuer string, authz services.Authorization, dpopVerifier dpop.Verifier) http.Handler {
	type response struct {
		Issuer     string `json:"issuer"`
		RequestURI string `json:"request_uri"`
		ExpiresIn  uint64 `json:"expires_in"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
			return
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
			json.NewEncoder(w).Encode(rfcerrors.InvalidClient().Build())
			return
		}

		// Check dpop proof
		jkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), dpopProof)
		if err != nil {
			log.Println("unable to validate dpop proof:", err)
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidDPoPProof().Build())
			return
		}

		// Prepare client request decoder
		clientRequestDecoder := jwsreq.AuthorizationRequestDecoder(jwt.DefaultVerifier(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
			var jwks jose.JSONWebKeySet
			if err := json.Unmarshal(client.Jwks, &jwks); err != nil {
				return nil, fmt.Errorf("unable to decode client JWKS")
			}

			// No error
			return &jwks, nil
		}, []jose.SignatureAlgorithm{jose.ES384}))

		// Decode request
		ar, err := clientRequestDecoder.Decode(ctx, requestRaw)
		if err != nil {
			log.Println("unable to decode request:", err)
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Send request to reactor
		res, err := authz.Register(ctx, &flowv1.RegistrationRequest{
			Issuer:  issuer,
			Client:  client,
			Request: ar,
			Confirmation: &tokenv1.TokenConfirmation{
				Jkt: jkt,
			},
		})
		if err != nil {
			log.Println("unable to register authorization request:", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		// Send json response
		respond.WithJSON(w, http.StatusCreated, &response{
			Issuer:     res.Issuer,
			RequestURI: res.RequestUri,
			ExpiresIn:  res.ExpiresIn,
		})
	})
}

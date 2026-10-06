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

package httpkit

import (
	"log"
	"net/http"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services"
)

// PushedAuthorizationRequest handles PAR HTTP requests.
func PushedAuthorizationRequest(issuer string, authz services.Authorization, dpopVerifier dpop.Verifier, requestObjectAlgorithms []string, profiles profile.Server) http.Handler {
	type response struct {
		Issuer     string `json:"issuer"`
		RequestURI string `json:"request_uri"`
		ExpiresIn  uint64 `json:"expires_in"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		var (
			ctx        = r.Context()
			q          = r.URL.Query()
			dpopProof  = r.Header.Get("DPoP")
			requestRaw = q.Get("request")
		)

		// Retrieve client front context. An unauthenticated caller is
		// an invalid_client per RFC 9126 §2.3 (RFC 6749 §5.2): 401
		// with WWW-Authenticate and the JSON error body.
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Check dpop proof
		jkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), dpopProof)
		if err != nil {
			log.Println("unable to validate dpop proof:", err)
			WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidDPoPProof().Build())
			return
		}

		// Prepare client request decoder
		clientRequestDecoder := clientRequestDecoder(client, issuer, requestObjectAlgorithms)

		// Decode request
		ar, err := clientRequestDecoder.Decode(ctx, requestRaw)
		if err != nil {
			log.Println("unable to decode request:", err)
			WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Enforce the application-type profile, when the client carries a
		// known application type: response types outside the profile are
		// rejected with 400 invalid_request (RFC 9126 flow: the request
		// is never registered).
		if !profile.AllowsResponseType(profiles, client.ApplicationType, ar.ResponseType) {
			WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
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
			// res may be nil on infrastructure failure; WithError is
			// nil-safe.
			if res != nil {
				WithError(w, r, http.StatusBadRequest, res.Error)
			} else {
				WithError(w, r, http.StatusBadRequest, nil)
			}
			return
		}

		// Send json response
		WithJSON(w, http.StatusCreated, &response{
			Issuer:     res.Issuer,
			RequestURI: res.RequestUri,
			ExpiresIn:  res.ExpiresIn,
		})
	})
}

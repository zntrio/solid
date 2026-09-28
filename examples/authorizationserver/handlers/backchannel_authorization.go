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
	"strconv"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
)

// BackchannelAuthorization handles CIBA backchannel authentication requests
// (OpenID CIBA Core 1.0 section 7).
func BackchannelAuthorization(issuer string, backchannelz services.BackchannelAuthentication) http.Handler {
	type response struct {
		AuthReqId string `json:"auth_req_id"`
		ExpiresIn uint64 `json:"expires_in"`
		Interval  uint64 `json:"interval"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			respond.WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		if err := r.ParseForm(); err != nil {
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Build the request message. When a signed request object is
		// used (CIBA section 7.1.1), no authentication request parameter
		// may be mapped from the form: they MUST NOT appear outside the
		// JWT; the client identity comes from the authenticated client.
		var req *flowv1.BackchannelAuthenticationRequest
		if requestObject := r.FormValue("request"); requestObject != "" {
			client, ok := clientauthentication.FromContext(r.Context())
			if !ok || client == nil {
				respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
				return
			}
			req = &flowv1.BackchannelAuthenticationRequest{
				Issuer:   issuer,
				ClientId: client.ClientId,
				Request:  optionalString(requestObject),
			}
		} else {
			// requested_expiry is OPTIONAL and numeric (CIBA section 7.1).
			var requestedExpiry *uint64
			if raw := r.FormValue("requested_expiry"); raw != "" {
				v, err := strconv.ParseUint(raw, 10, 64)
				if err != nil {
					respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
					return
				}
				requestedExpiry = &v
			}

			// authorization_details is OPTIONAL (RFC 9396 with CIBA
			// section 7.1); absent means empty.
			authorizationDetails := []*tokenv1.AuthorizationDetail{}
			if raw := r.FormValue("authorization_details"); raw != "" {
				details, err := parseAuthorizationDetails(raw)
				if err != nil {
					respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
					return
				}
				authorizationDetails = details
			}

			req = &flowv1.BackchannelAuthenticationRequest{
				Issuer:               issuer,
				ClientId:             r.FormValue("client_id"),
				Scope:                optionalString(r.FormValue("scope")),
				Audience:             optionalString(r.FormValue("audience")),
				AcrValues:            optionalString(r.FormValue("acr_values")),
				LoginHint:            optionalString(r.FormValue("login_hint")),
				LoginHintToken:       optionalString(r.FormValue("login_hint_token")),
				IdTokenHint:          optionalString(r.FormValue("id_token_hint")),
				BindingMessage:       optionalString(r.FormValue("binding_message")),
				RequestedExpiry:      requestedExpiry,
				AuthorizationDetails: authorizationDetails,
				DpopJkt:              optionalString(r.FormValue("dpop_jkt")),
			}
		}

		// Send to reactor
		res, err := backchannelz.Authorize(r.Context(), req)
		if err != nil {
			log.Println("unable to process backchannel authentication request:", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		// Send json response
		respond.WithJSON(w, http.StatusOK, &response{
			AuthReqId: res.AuthReqId,
			ExpiresIn: res.ExpiresIn,
			Interval:  res.Interval,
		})
	})
}

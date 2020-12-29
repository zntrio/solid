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
	"fmt"
	"log"
	"net/http"

	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/authorizationserver"
)

// DeviceAuthorization handles device authorization HTTP requests.
func DeviceAuthorization(as authorizationserver.AuthorizationServer) http.Handler {
	type response struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       uint64 `json:"expires_in"`
		Interval        uint64 `json:"interval"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			withError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		r.ParseForm()

		// Parameters
		var (
			ctx         = r.Context()
			clientIDRaw = r.FormValue("client_id")
			scopeRaw    = r.FormValue("scope")
			audienceRaw = r.FormValue("audience")
		)

		// Prepare request
		req := &corev1.DeviceAuthorizationRequest{
			ClientId: clientIDRaw,
		}
		if scopeRaw != "" {
			req.Scope = &wrapperspb.StringValue{
				Value: scopeRaw,
			}
		}
		if audienceRaw != "" {
			req.Audience = &wrapperspb.StringValue{
				Value: audienceRaw,
			}
		}

		// Send to reactor
		res, err := as.Do(ctx, req)
		authRes, ok := res.(*corev1.DeviceAuthorizationResponse)
		if !ok {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}
		if err != nil {
			log.Println("unable to process device authorization request:", err)
			withError(w, r, http.StatusBadRequest, authRes.Error)
			return
		}

		// Send json reponse
		withJSON(w, r, http.StatusOK, &response{
			DeviceCode:      authRes.DeviceCode,
			UserCode:        authRes.UserCode,
			VerificationURI: fmt.Sprintf("%s/device", as.Issuer()),
			ExpiresIn:       authRes.ExpiresIn,
			Interval:        authRes.Interval,
		})
	})
}

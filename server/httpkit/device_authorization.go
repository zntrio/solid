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
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/services"
)

// DeviceAuthorization handles device authorization HTTP requests.
func DeviceAuthorization(issuer string, devicez services.Device, verificationURI string) http.Handler {
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
			WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		if err := r.ParseForm(); err != nil {
			WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Parameters
		ctx := r.Context()

		// Send to reactor
		res, err := devicez.Authorize(ctx, &flowv1.DeviceAuthorizationRequest{
			Issuer:   issuer,
			ClientId: r.FormValue("client_id"),
			Scope:    optionalString(r.FormValue("scope")),
			Audience: optionalString(r.FormValue("audience")),
		})
		if err != nil {
			log.Println("unable to process device authorization request:", err)
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
		WithJSON(w, http.StatusOK, &response{
			DeviceCode:      res.DeviceCode,
			UserCode:        res.UserCode,
			VerificationURI: verificationURI,
			ExpiresIn:       res.ExpiresIn,
			Interval:        res.Interval,
		})
	})
}

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
	"html/template"
	"log"
	"net/http"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/examples/authorizationserver/middleware"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/services"
)

// BackchannelValidation handles the end-user approval of a backchannel
// authentication request on the authentication device (OpenID CIBA Core 1.0
// section 8). Only the approval path is exposed by this example; the deny
// path stays service-level.
func BackchannelValidation(issuer string, backchannelz services.BackchannelAuthentication) http.Handler {
	// Display auth_req_id form
	displayForm := func(w http.ResponseWriter, r *http.Request) {
		// Only GET verb
		if r.Method != http.MethodGet {
			respond.WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Prepare template
		form := template.Must(template.New("auth-req-id-input").Parse(`<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
	<form action="" method="post">
	  <label for="auth_req_id">Enter auth_req_id:
		  <input type="text" name="auth_req_id">
	  </label>
	</form>
  </body>
</html>`))

		// Write template to output
		if err := form.Execute(w, nil); err != nil {
			respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}
	}

	// Validate auth_req_id
	validateAuthReqID := func(w http.ResponseWriter, r *http.Request, sub string) {
		if err := r.ParseForm(); err != nil {
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Only POST verb
		if r.Method != http.MethodPost {
			respond.WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Send request to reactor
		res, err := backchannelz.Validate(r.Context(), &flowv1.BackchannelAuthenticationValidationRequest{
			Issuer:    issuer,
			Subject:   sub,
			AuthReqId: r.PostFormValue("auth_req_id"),
		})
		if err != nil {
			log.Println("unable to process backchannel validation request:", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Retrieve subject form context
		sub, ok := middleware.Subject(ctx)
		if !ok || sub == "" {
			respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
			return
		}

		switch r.Method {
		case http.MethodGet:
			displayForm(w, r)
		case http.MethodPost:
			validateAuthReqID(w, r, sub)
		default:
			respond.WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}
	})
}

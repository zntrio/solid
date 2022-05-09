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

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/examples/server/middleware"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/services"
)

// Device handle device code validation.
func Device(issuer string, devicez services.Device) http.Handler {
	// Display user code form
	displayForm := func(w http.ResponseWriter, r *http.Request, sub string) {
		// Only POST verb
		if r.Method != http.MethodGet {
			withError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Prepare template
		form := template.Must(template.New("user-code-inupt").Parse(`<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
	<form action="" method="post">
	  <label for="user_code">Enter user code:
		  <input type="text" name="user_code">
	  </label>
	</form>
  </body>
</html>`))

		// Write template to output
		if err := form.Execute(w, nil); err != nil {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}
	}

	// Validate user code
	validateUserCode := func(w http.ResponseWriter, r *http.Request, sub string) {
		r.ParseForm()

		// Only POST verb
		if r.Method != http.MethodPost {
			withError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Send request to reactor
		res, err := devicez.Validate(r.Context(), &corev1.DeviceCodeValidationRequest{
			Issuer:   issuer,
			Subject:  sub,
			UserCode: r.PostFormValue("user_code"),
		})
		if err != nil {
			log.Println("unable to process authorization request:", err)
			withError(w, r, http.StatusBadRequest, res.Error)
			return
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Retrieve subject form context
		sub, ok := middleware.Subject(ctx)
		if !ok || sub == "" {
			withError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
			return
		}

		switch r.Method {
		case http.MethodGet:
			displayForm(w, r, sub)
		case http.MethodPost:
			validateUserCode(w, r, sub)
		default:
			withError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}
	})
}

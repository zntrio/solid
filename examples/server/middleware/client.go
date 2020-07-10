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

package middleware

import (
	"encoding/json"
	"log"
	"net/http"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/server/clientauthentication"
	"zntr.io/solid/pkg/server/storage"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// ClientAuthentication is a middleware to handle client authentication.
func ClientAuthentication(clients storage.ClientReader) Adapter {
	// Prepare client authentication
	clientAuth := clientauthentication.PrivateKeyJWT(clients)

	// Return middleware
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ctx = r.Context()
				q   = r.URL.Query()
			)

			// Process authentication
			resAuth, err := clientAuth.Authenticate(ctx, &corev1.ClientAuthenticationRequest{
				ClientAssertionType: &wrappers.StringValue{
					Value: q.Get("client_assertion_type"),
				},
				ClientAssertion: &wrappers.StringValue{
					Value: q.Get("client_assertion"),
				},
			})
			if err != nil {
				log.Println("unable to authenticate client:", err)
				json.NewEncoder(w).Encode(resAuth.GetError())
				return
			}

			// Assign client to context
			ctx = clientauthentication.Inject(ctx, resAuth.Client)

			// Delegate to next handler
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

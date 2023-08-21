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
	"log"
	"net/http"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/storage"
)

// ClientAuthentication is a middleware to handle client authentication.
func ClientAuthentication(clients storage.ClientReader) Adapter {
	// Prepare client authentication
	clientAuth := clientauthentication.PrivateKeyJWT(clients)
	clientAttestationAuth := clientauthentication.ClientAttestation(clients)

	// Return middleware
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ctx         = r.Context()
				q           = r.URL.Query()
				clientIDRaw = q.Get("client_id")
			)

			if clientIDRaw != "" {
				// Retrieve client details
				client, err := clients.Get(ctx, clientIDRaw)
				if err != nil {
					log.Println("unable to retrieve client:", err)
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}

				if client.ClientType == corev1.ClientType_CLIENT_TYPE_PUBLIC {
					// Assign client to context
					ctx = clientauthentication.Inject(ctx, client)
				} else {
					log.Println("missing client authentication")
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}
			} else {
				r.ParseForm()

				var (
					authMethod = r.PostFormValue("client_assertion_type")
					assertion = r.PostFormValue("client_assertion")
					authenticator clientauthentication.AuthenticationProcessor
				)

				switch authMethod {
				case oidc.AssertionTypeJWTBearer:
					authenticator = clientAuth
				case oidc.AssertionTypeJWTClientAttestation:
					authenticator = clientAttestationAuth
				default:
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
					return
				}

				// Process authentication
				resAuth, err := authenticator.Authenticate(ctx, &corev1.ClientAuthenticationRequest{
					ClientAssertionType: types.StringRef(authMethod),
					ClientAssertion:     types.StringRef(assertion),
				})
				if err != nil {
					log.Println("unable to authenticate client:", err)
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}
									
				// Assign client to context
				ctx = clientauthentication.Inject(ctx, resAuth.Client)
			}

			// Delegate to next handler
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

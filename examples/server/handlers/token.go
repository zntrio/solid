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
	"time"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/authorizationserver"
	"go.zenithar.org/solid/pkg/clientauthentication"
	"go.zenithar.org/solid/pkg/rfcerrors"
)

// Token handles token HTTP requests.
func Token(as authorizationserver.AuthorizationServer) http.Handler {
	type response struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    uint64 `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope"`
	}

	messageBuilder := func(r *http.Request, client *corev1.Client) *corev1.TokenRequest {
		var (
			q         = r.URL.Query()
			grantType = q.Get("grant_type")
		)

		msg := &corev1.TokenRequest{
			Client:    client,
			GrantType: grantType,
		}

		switch grantType {
		case oidc.GrantTypeAuthorizationCode:
			msg.Grant = &corev1.TokenRequest_AuthorizationCode{
				AuthorizationCode: &corev1.GrantAuthorizationCode{
					Code:         q.Get("code"),
					CodeVerifier: q.Get("code_verifier"),
					RedirectUri:  q.Get("redirect_uri"),
				},
			}
		case oidc.GrantTypeClientCredentials:
			msg.Grant = &corev1.TokenRequest_ClientCredentials{
				ClientCredentials: &corev1.GrantClientCredentials{
					Audience: q.Get("audience"),
					Scope:    q.Get("scope"),
				},
			}
		case oidc.GrantTypeDeviceCode:
			msg.Grant = &corev1.TokenRequest_DeviceCode{
				DeviceCode: &corev1.GrantDeviceCode{},
			}
		case oidc.GrantTypeRefreshToken:
			msg.Grant = &corev1.TokenRequest_RefreshToken{
				RefreshToken: &corev1.GrantRefreshToken{
					RefreshToken: q.Get("refresh_token"),
				},
			}
		}

		// Return request
		return msg
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx = r.Context()
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			withJSON(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient(""))
			return
		}

		// Send request to reactor
		res, err := as.Do(r.Context(), messageBuilder(r, client))
		tokenRes, ok := res.(*corev1.TokenResponse)
		if !ok {
			withJSON(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to process token request: %w", err)
			withJSON(w, r, http.StatusBadRequest, tokenRes.Error)
			return
		}

		// Prepare response
		jsonResponse := &response{
			AccessToken: tokenRes.AccessToken.Value,
			ExpiresIn:   tokenRes.AccessToken.Metadata.ExpiresAt - uint64(time.Now().Unix()),
			TokenType:   "Bearer",
			Scope:       tokenRes.AccessToken.Metadata.Scope,
		}
		if tokenRes.RefreshToken != nil {
			jsonResponse.RefreshToken = tokenRes.RefreshToken.Value
		}

		// Send json reponse
		withJSON(w, r, http.StatusOK, jsonResponse)
	})
}

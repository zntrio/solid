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

	"github.com/davecgh/go-spew/spew"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
)

// Token handles token HTTP requests.
func Token(issuer string, tokenz services.Token, dpopVerifier dpop.Verifier) http.Handler {
	type response struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    uint64 `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope"`
	}

	messageBuilder := func(r *http.Request, client *corev1.Client) *corev1.TokenRequest {
		grantType := r.FormValue("grant_type")

		msg := &corev1.TokenRequest{
			Issuer:    issuer,
			Client:    client,
			GrantType: grantType,
		}

		switch grantType {
		case oidc.GrantTypeAuthorizationCode:
			msg.Grant = &corev1.TokenRequest_AuthorizationCode{
				AuthorizationCode: &corev1.GrantAuthorizationCode{
					Code:         r.FormValue("code"),
					CodeVerifier: r.FormValue("code_verifier"),
					RedirectUri:  r.FormValue("redirect_uri"),
				},
			}
		case oidc.GrantTypeClientCredentials:
			msg.Grant = &corev1.TokenRequest_ClientCredentials{
				ClientCredentials: &corev1.GrantClientCredentials{},
			}
		case oidc.GrantTypeDeviceCode:
			msg.Grant = &corev1.TokenRequest_DeviceCode{
				DeviceCode: &corev1.GrantDeviceCode{
					DeviceCode: r.FormValue("device_code"),
				},
			}
		case oidc.GrantTypeRefreshToken:
			msg.Grant = &corev1.TokenRequest_RefreshToken{
				RefreshToken: &corev1.GrantRefreshToken{
					RefreshToken: r.FormValue("refresh_token"),
				},
			}
		}

		// Return request
		return msg
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			respond.WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		var (
			ctx       = r.Context()
			dpopProof = r.Header.Get("DPoP")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Prepare msg
		msg := messageBuilder(r, client)

		if dpopProof != "" {
			// Check dpop proof
			jkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), dpopProof)
			if err != nil {
				log.Println("unable to validate dpop proof:", err)
				respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidDPoPProof().Build())
				return
			}

			// Add confirmation
			msg.TokenConfirmation = &corev1.TokenConfirmation{
				Jkt: jkt,
			}
		}

		// Send request to reactor
		res, err := tokenz.Token(ctx, msg)
		if err != nil {
			log.Println("unable to process token request:", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		// Change token type according to DPoP usage.
		tokenType := "Bearer"
		if dpopProof != "" {
			tokenType = "DPoP"
		}

		spew.Dump(res)

		// Prepare response
		jsonResponse := &response{
			AccessToken: res.AccessToken.Value,
			ExpiresIn:   res.AccessToken.Metadata.ExpiresAt - uint64(time.Now().Unix()),
			TokenType:   tokenType,
			Scope:       res.AccessToken.Metadata.Scope,
		}
		if res.RefreshToken != nil {
			jsonResponse.RefreshToken = res.RefreshToken.Value
		}

		// Send json reponse
		respond.WithJSON(w, r, http.StatusOK, jsonResponse)
	})
}

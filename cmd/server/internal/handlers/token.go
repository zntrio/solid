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

	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/dpop"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/authorizationserver"
	"zntr.io/solid/pkg/server/clientauthentication"
)

// Token handles token HTTP requests.
func Token(as authorizationserver.AuthorizationServer, dpopVerifier dpop.Verifier) http.Handler {
	type response struct {
		Issuer          string `json:"iss"`
		AccessToken     string `json:"access_token"`
		ExpiresIn       uint64 `json:"expires_in"`
		TokenType       string `json:"token_type"`
		RefreshToken    string `json:"refresh_token,omitempty"`
		Scope           string `json:"scope,omitempty"`
		IssuedTokenType string `json:"issued_token_type,omitempty"`
	}

	messageBuilder := func(r *http.Request, client *corev1.Client) *corev1.TokenRequest {
		r.ParseForm()

		var (
			grantType = r.FormValue("grant_type")
			scope     = r.FormValue("scope")
			resource  = r.FormValue("resource")
			audience  = r.FormValue("audience")
		)

		msg := &corev1.TokenRequest{
			Issuer:    as.Issuer().String(),
			Client:    client,
			GrantType: grantType,
		}

		if scope != "" {
			msg.Scope = &wrapperspb.StringValue{Value: scope}
		}
		if resource != "" {
			msg.Resource = &wrapperspb.StringValue{Value: resource}
		}
		if audience != "" {
			msg.Audience = &wrapperspb.StringValue{Value: audience}
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
				ClientCredentials: &corev1.GrantClientCredentials{
					Audience: r.FormValue("audience"),
					Scope:    r.FormValue("scope"),
				},
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

		case oidc.GrantTypeTokenExchange:
			msg.Grant = &corev1.TokenRequest_TokenExchange{
				TokenExchange: &corev1.GrantTokenExchange{
					SubjectToken:       r.FormValue("subject_token"),
					SubjectTokenType:   r.FormValue("subject_token_type"),
					ActorToken:         optionalString(r.FormValue("actor_token")),
					ActorTokenType:     optionalString(r.FormValue("actor_token_type")),
					RequestedTokenType: optionalString(r.FormValue("requested_token_type")),
				},
			}
		}

		// Return request
		return msg
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx       = r.Context()
			dpopProof = r.Header.Get("DPoP")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			withError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Prepare msg
		msg := messageBuilder(r, client)

		if dpopProof != "" {
			// Check dpop proof
			jkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), dpopProof)
			if err != nil {
				log.Println("unable to validate dpop proof:", err)
				withError(w, r, http.StatusBadRequest, rfcerrors.InvalidDPoPProof().Build())
				return
			}

			// Add confirmation
			msg.TokenConfirmation = &corev1.TokenConfirmation{
				Jkt: jkt,
			}
		}

		// Send request to reactor
		res, err := as.Do(r.Context(), msg)
		tokenRes, ok := res.(*corev1.TokenResponse)
		if !ok {
			withError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}
		if err != nil {
			log.Println("unable to process token request:", err)
			withError(w, r, http.StatusBadRequest, tokenRes.Error)
			return
		}

		// Change token type according to DPoP usage.
		tokenType := "Bearer"
		if dpopProof != "" {
			tokenType = "DPoP"
		}

		// Prepare response
		jsonResponse := &response{
			Issuer:      tokenRes.Issuer,
			AccessToken: tokenRes.AccessToken.Value,
			ExpiresIn:   tokenRes.AccessToken.Metadata.ExpiresAt - uint64(time.Now().Unix()),
			TokenType:   tokenType,
			Scope:       tokenRes.AccessToken.Metadata.Scope,
		}
		if tokenRes.RefreshToken != nil {
			jsonResponse.RefreshToken = tokenRes.RefreshToken.Value
		}
		if tokenRes.IssuedTokenType != "" {
			jsonResponse.IssuedTokenType = tokenRes.IssuedTokenType
		}

		// Send json reponse
		withJSON(w, r, http.StatusOK, jsonResponse)
	})
}

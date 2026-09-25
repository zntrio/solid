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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
)

// Token handles token HTTP requests.
func Token(issuer string, tokenz services.Token, dpopVerifier dpop.Verifier) http.Handler {
	type response struct {
		AccessToken          string                         `json:"access_token"`
		ExpiresIn            uint64                         `json:"expires_in"`
		TokenType            string                         `json:"token_type"`
		RefreshToken         string                         `json:"refresh_token,omitempty"`
		Scope                string                         `json:"scope"`
		AuthorizationDetails []*tokenv1.AuthorizationDetail `json:"authorization_details,omitempty"`
	}

	messageBuilder := func(r *http.Request, client *clientv1.Client) (*flowv1.TokenRequest, error) {
		grantType := r.FormValue("grant_type")

		msg := &flowv1.TokenRequest{
			Issuer:    issuer,
			Client:    client,
			GrantType: grantType,
		}

		switch grantType {
		case oidc.GrantTypeAuthorizationCode:
			msg.Grant = &flowv1.TokenRequest_AuthorizationCode{
				AuthorizationCode: &flowv1.GrantAuthorizationCode{
					Code:         r.FormValue("code"),
					CodeVerifier: r.FormValue("code_verifier"),
					RedirectUri:  r.FormValue("redirect_uri"),
				},
			}
		case oidc.GrantTypeClientCredentials:
			msg.Grant = &flowv1.TokenRequest_ClientCredentials{
				ClientCredentials: &flowv1.GrantClientCredentials{},
			}
		case oidc.GrantTypeDeviceCode:
			msg.Grant = &flowv1.TokenRequest_DeviceCode{
				DeviceCode: &flowv1.GrantDeviceCode{
					DeviceCode: r.FormValue("device_code"),
				},
			}
		case oidc.GrantTypeRefreshToken:
			msg.Grant = &flowv1.TokenRequest_RefreshToken{
				RefreshToken: &flowv1.GrantRefreshToken{
					RefreshToken: r.FormValue("refresh_token"),
				},
			}
		}

		// RFC 9396 section 6: the authorization_details request parameter
		// is a JSON array of objects. The grant services compare each entry
		// against the consented set; malformed JSON is rejected here.
		if raw := r.FormValue("authorization_details"); raw != "" {
			details, errParse := parseAuthorizationDetails(raw)
			if errParse != nil {
				return nil, errParse
			}
			msg.AuthorizationDetails = details
		}

		// Return request
		return msg, nil
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
		msg, errBuild := messageBuilder(r, client)
		if errBuild != nil {
			log.Println("unable to parse token request:", errBuild)
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidAuthorizationDetails().Build())
			return
		}

		// Ensure DPoP enabled to use use DPoP.
		if dpopProof == "" && client.DpopBoundAccessTokens {
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}
		if dpopProof != "" {
			// Check dpop proof
			jkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), dpopProof)
			if err != nil {
				log.Println("unable to validate dpop proof:", err)
				respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidDPoPProof().Build())
				return
			}

			// Add confirmation
			msg.TokenConfirmation = &tokenv1.TokenConfirmation{
				Jkt: jkt,
			}

			// RFC 9449 section 10: carry the verified thumbprint on the
			// authorization code grant so the service can enforce the code's
			// key binding.
			if ac := msg.GetAuthorizationCode(); ac != nil {
				ac.DpopJkt = &jkt
			}
		}

		// RFC 8705 section 3: when the token request is made over mutual TLS
		// with a client certificate, bind the issued token to that certificate.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if msg.TokenConfirmation == nil {
				msg.TokenConfirmation = &tokenv1.TokenConfirmation{}
			}
			msg.TokenConfirmation.X5TS256 = token.X509ThumbprintS256(r.TLS.PeerCertificates[0])
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

		// RFC 9396 section 7: the granted authorization_details MUST be
		// returned in the token response.
		if len(res.AuthorizationDetails) > 0 {
			jsonResponse.AuthorizationDetails = res.AuthorizationDetails
		}

		// Send json reponse
		respond.WithJSON(w, http.StatusOK, jsonResponse)
	})
}

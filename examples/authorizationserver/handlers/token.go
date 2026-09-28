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
	"context"
	"log"
	"net/http"
	"time"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
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

// bearerTokenType is the default OAuth 2.0 token type.
const bearerTokenType = "Bearer"

// dpopTokenType is the token type for DPoP-bound access tokens (RFC 9449 §6).
const dpopTokenType = "DPoP"

// tokenEndpointResponse is the successful token endpoint JSON body
// (draft-ietf-oauth-v2-1-16 §3.2.2.1).
type tokenEndpointResponse struct {
	AccessToken          string                         `json:"access_token"`
	ExpiresIn            uint64                         `json:"expires_in"`
	TokenType            string                         `json:"token_type"`
	RefreshToken         string                         `json:"refresh_token,omitempty"`
	Scope                string                         `json:"scope"`
	AuthorizationDetails []*tokenv1.AuthorizationDetail `json:"authorization_details,omitempty"`
}

// Token handles token HTTP requests.
func Token(issuer string, tokenz services.Token, dpopVerifier dpop.Verifier) http.Handler {
	messageBuilder := func(r *http.Request, client *clientv1.Client) (*flowv1.TokenRequest, error) {
		msg := &flowv1.TokenRequest{
			Issuer:    issuer,
			Client:    client,
			GrantType: r.FormValue("grant_type"),
		}

		setGrantFromRequest(msg, r)

		// draft-ietf-oauth-v2-1-16 §4.3.1 (RFC 6749 §6): a refresh request
		// may carry a scope parameter; grant services enforce the
		// narrowing rule.
		if v := r.FormValue("scope"); v != "" {
			msg.Scope = &v
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
		if err := applyDPoPConfirmation(ctx, msg, r, dpopProof, dpopVerifier); err != nil {
			respond.WithError(w, r, http.StatusBadRequest, err)
			return
		}

		// RFC 8705 section 3: when the token request is made over mutual TLS
		// with a client certificate, bind the issued token to that certificate.
		applyClientCertificateBinding(msg, r)

		// Send request to reactor
		res, err := tokenz.Token(ctx, msg)
		if err != nil {
			log.Println("unable to process token request:", err)
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		// Prepare and send the JSON response.
		writeTokenResponse(w, res)
	})
}

// tokenResponseType resolves the token_type of an issued access token:
// RFC 9449 section 6 — DPoP-bound tokens (cnf.jkt set at mint time) MUST
// signal "DPoP", everything else is "Bearer".
func tokenResponseType(at *tokenv1.Token) string {
	if at != nil && at.Confirmation != nil && at.Confirmation.Jkt != "" {
		return dpopTokenType
	}
	return bearerTokenType
}

// writeTokenResponse serializes the successful token response as JSON,
// including the refresh token and authorization details when present
// (RFC 9396 section 7).
func writeTokenResponse(w http.ResponseWriter, res *flowv1.TokenResponse) {
	// Prepare response
	jsonResponse := &tokenEndpointResponse{
		AccessToken: res.AccessToken.Value,
		ExpiresIn:   res.AccessToken.Metadata.ExpiresAt - uint64(time.Now().Unix()), //nolint:gosec // unix time is non-negative
		TokenType:   tokenResponseType(res.AccessToken),
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

	// Send json response
	respond.WithJSON(w, http.StatusOK, jsonResponse)
}

// applyDPoPConfirmation verifies the DPoP proof, when present, and records
// the resulting key thumbprint as token confirmation on the request message.
func applyDPoPConfirmation(ctx context.Context, msg *flowv1.TokenRequest, r *http.Request, dpopProof string, dpopVerifier dpop.Verifier) *corev1.Error {
	if dpopProof == "" {
		return nil
	}
	// Check dpop proof
	jkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), dpopProof)
	if err != nil {
		log.Println("unable to validate dpop proof:", err)
		return rfcerrors.InvalidDPoPProof().Build()
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
	return nil
}

// grantFromRequest extracts the grant-specific request parameters according
// to the requested grant type.
func setGrantFromRequest(msg *flowv1.TokenRequest, r *http.Request) {
	switch r.FormValue("grant_type") {
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
	case oidc.GrantTypeCIBA:
		msg.Grant = &flowv1.TokenRequest_Ciba{
			Ciba: &flowv1.GrantCIBA{
				AuthReqId: r.FormValue("auth_req_id"),
				ClientId:  r.FormValue("client_id"),
			},
		}
	}
}

// applyClientCertificateBinding binds the issued token to the client
// certificate presented over mutual TLS (RFC 8705 section 3).
func applyClientCertificateBinding(msg *flowv1.TokenRequest, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return
	}

	if msg.TokenConfirmation == nil {
		msg.TokenConfirmation = &tokenv1.TokenConfirmation{}
	}
	msg.TokenConfirmation.X5TS256 = token.X509ThumbprintS256(r.TLS.PeerCertificates[0])
}

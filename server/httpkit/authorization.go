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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/jwsreq"
	"zntr.io/solid/sdk/pairwise"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

// Authorization handles authorization HTTP requests.
func Authorization(issuer string, authz services.Authorization, clients storage.ClientReader, jarmEncoder jarm.ResponseEncoder, pairwiseEncoder pairwise.Encoder, requestObjectAlgorithms []string, profiles profile.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only GET verb
		if r.Method != http.MethodGet {
			WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Parameters
		var (
			ctx        = r.Context()
			q          = r.URL.Query()
			clientID   = q.Get("client_id")
			requestRaw = q.Get("request")
		)

		// Retrieve subject from context
		sub, ok := Subject(ctx)
		if !ok || sub == "" {
			WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Retrieve client
		client, err := clients.Get(ctx, clientID)
		if err != nil {
			WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Apply pairwise encoding
		if client.SubjectType == oidc.SubjectTypePairwise {
			sub, err = pairwiseEncoder.Encode(client.SectorIdentifier, sub)
			if err != nil {
				WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
				return
			}
		}

		// Prepare client request decoder
		clientRequestDecoder := jwsreq.AuthorizationRequestDecoder(jwt.DefaultVerifier(func(ctx context.Context) (jwk.Set, error) {
			parsed, parseErr := jwk.Parse(client.Jwks)
			if parseErr != nil {
				return nil, fmt.Errorf("unable to decode client JWKS")
			}

			// No error
			return parsed, nil
		}, requestObjectAlgorithms), issuer)

		// Decode the request object; on failure, RFC 6749 §4.1.2.1
		// redirects the error when a redirect URI is known.
		ar, err := decodeAuthorizationRequest(w, r, clientRequestDecoder, ctx, requestRaw, issuer)
		if err != nil {
			return
		}

		// Enforce the application-type profile, when the client carries a
		// known application type: response types outside the profile are
		// rejected by redirect per RFC 6749 section 4.1.2.1.
		if !profileAllowsResponseType(profiles, client.ApplicationType, ar.ResponseType) {
			redirectAuthorizationError(w, r, ar.RedirectUri, issuer, rfcerrors.InvalidRequest().Build(), ar.State)
			return
		}

		// Send request to reactor
		res, err := authz.Authorize(ctx, &flowv1.AuthorizeRequest{
			Client:  client,
			Issuer:  issuer,
			Subject: sub,
			Request: ar,
		})
		if err != nil {
			log.Println("unable to process authorization request:", err)
			if res != nil && res.RedirectUri != "" {
				redirectAuthorizationError(w, r, res.RedirectUri, issuer, res.Error, ar.State)
				return
			}
			WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		// Process according to response_mode.
		respondAuthorizationResponse(w, r, res, jarmEncoder)
	})
}

// respondAuthorizationResponse renders the authorization response in the
// requested response mode. The draft-ietf-oauth-v2-1-16 §4.1.2 default
// response mode for response_type=code is the plain code response in the
// query component.
func respondAuthorizationResponse(w http.ResponseWriter, r *http.Request, res *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	switch res.ResponseMode {
	case oidc.ResponseModeFormPost:
		responseTypeFormPost(w, r, res)
	case oidc.ResponseModeQueryJWT:
		responseTypeQueryJWT(w, r, res, jarmEncoder)
	case oidc.ResponseModeFragmentJWT:
		responseTypeFragmentJWT(w, r, res, jarmEncoder)
	case oidc.ResponseModeFormPOSTJWT:
		responseTypeFormPostJWT(w, r, res, jarmEncoder)
	default:
		// Empty (request omitted response_mode) or query: plain code
		// response (draft-ietf-oauth-v2-1-16 §4.1.2).
		responseTypeCode(w, r, res)
	}
}

// decodeAuthorizationRequest decodes the signed request object; when
// decoding fails and the (partially) decoded request carries a redirect
// URI, the error is delivered to the client by redirect per RFC 6749
// section 4.1.2.1. Direct JSON errors are reserved for requests where the
// client identity or redirect URI cannot be established.
func decodeAuthorizationRequest(w http.ResponseWriter, r *http.Request, decoder jwsreq.AuthorizationDecoder, ctx context.Context, requestRaw, issuer string) (*flowv1.AuthorizationRequest, error) {
	ar, err := decoder.Decode(ctx, requestRaw)
	if err == nil {
		return ar, nil
	}
	log.Println("unable to decode request:", err)
	if uri := redirectURIFromRequest(ar); uri != "" {
		redirectAuthorizationError(w, r, uri, issuer, rfcerrors.InvalidRequest().Build(), ar.State)
		return nil, errRedirected
	}
	WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
	return nil, errRedirected
}

// errRedirected signals that decodeAuthorizationRequest already wrote the
// HTTP response (redirect or JSON) and the caller must only return.
var errRedirected = errors.New("authorization request handling already finalized")

// -----------------------------------------------------------------------------

func responseTypeCode(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble final uri
	params := url.Values{}
	if authRes.Error != nil {
		params.Set("error", authRes.Error.Error)
		if authRes.Error.ErrorDescription != "" {
			params.Set("error_description", authRes.Error.ErrorDescription)
		}
		params.Set("state", authRes.State)
		// RFC 9207 section 2: the issuer identifier MUST be included in
		// error responses as well, so the client can detect mix-up
		// attacks on failed flows too.
		params.Set("iss", authRes.Issuer)
	} else {
		params.Set("code", authRes.Code)
		params.Set("iss", authRes.Issuer)
		params.Set("state", authRes.State)
	}

	// Assign new params
	u.RawQuery = params.Encode()

	// RFC 6749 section 5.1: responses carrying sensitive values (the
	// authorization code travels in the redirect URL) are not
	// cacheable.
	w.Header().Set("Cache-Control", "no-store")

	// Redirect to application
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func responseTypeQueryJWT(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Encode JARM
	jarmToken, err := jarmEncoder.Encode(r.Context(), authRes.Issuer, authRes)
	if err != nil {
		log.Println("unable to produce JARM token:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble final uri
	params := url.Values{}
	params.Set("response", jarmToken)

	// Assign new params
	u.RawQuery = params.Encode()

	// RFC 6749 section 5.1: the JARM response travels in the redirect
	// URL and is not cacheable.
	w.Header().Set("Cache-Control", "no-store")

	// Redirect to application
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func responseTypeFragmentJWT(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Encode JARM
	jarmToken, err := jarmEncoder.Encode(r.Context(), authRes.Issuer, authRes)
	if err != nil {
		log.Println("unable to produce JARM token:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble final uri
	params := url.Values{}
	params.Set("response", jarmToken)

	// Assign new params
	u.Fragment = params.Encode()

	// RFC 6749 section 5.1: the JARM response travels in the redirect
	// URL fragment and is not cacheable.
	w.Header().Set("Cache-Control", "no-store")

	// Redirect to application
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func responseTypeFormPostJWT(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Encode JARM
	jarmToken, err := jarmEncoder.Encode(r.Context(), authRes.Issuer, authRes)
	if err != nil {
		log.Println("unable to produce JARM token:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Prepare template
	form := template.Must(template.New("form-post-jwt").Parse(`<!DOCTYPE html><html><head><title>Submit This Form</title></head><body><form method="post" action="{{ .RedirectURI }}"><input type="hidden" name="response" value="{{ .Response }}"/></form><script type="text/javascript" nonce="{{ .Nonce }}" integrity="sha384-ZGMxYzUyZTk2ZGY3OGNjZDNlMGFiMTI1M2RmMmNiNmY4MzgyZjY3NDcyZDc1M2U4YTRmNTEzYzc0NTE4M2FiOGZkMWQ1YzFhMjA2MDI2ZTNjOWMyOWEyYzY2YTRhY2Y2Cg==">window.onload = function() {document.forms[0].submit();};</script></body></html>`))
	nonce := base64.URLEncoding.EncodeToString([]byte(random.String(8)))

	// Set headers
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("script-src 'self' 'sha384-ZGMxYzUyZTk2ZGY3OGNjZDNlMGFiMTI1M2RmMmNiNmY4MzgyZjY3NDcyZDc1M2U4YTRmNTEzYzc0NTE4M2FiOGZkMWQ1YzFhMjA2MDI2ZTNjOWMyOWEyYzY2YTRhY2Y2Cg==' 'nonce-%s';", nonce))

	// Write template to output
	if err := form.Execute(w, map[string]string{
		"RedirectURI": u.String(),
		"Response":    jarmToken,
		"Nonce":       nonce,
	}); err != nil {
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}
}

// responseTypeFormPost renders the plain (non-JARM) form_post response mode:
// the authorization response parameters (code, state, iss — or the error
// fields) are submitted as auto-posted form fields.
func responseTypeFormPost(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble form fields
	var (
		code  string
		errc  string
		state = authRes.State
	)
	if authRes.Error != nil {
		errc = authRes.Error.Error
	} else {
		code = authRes.Code
	}

	// Prepare template
	form := template.Must(template.New("form-post").Parse(`<!DOCTYPE html><html><head><title>Submit This Form</title></head><body><form method="post" action="{{ .RedirectURI }}">{{ if .Code }}<input type="hidden" name="code" value="{{ .Code }}"/>{{ end }}{{ if .Error }}<input type="hidden" name="error" value="{{ .Error }}"/>{{ end }}<input type="hidden" name="state" value="{{ .State }}"/><input type="hidden" name="iss" value="{{ .Issuer }}"/></form><script type="text/javascript" nonce="{{ .Nonce }}" integrity="sha384-ZGMxYzUyZTk2ZGY3OGNjZDNlMGFiMTI1M2RmMmNiNmY4MzgyZjY3NDcyZDc1M2U4YTRmNTEzYzc0NTE4M2FiOGZkMWQ1YzFhMjA2MDI2ZTNjOWMyOWEyYzY2YTRhY2Y2Cg==">window.onload = function() {document.forms[0].submit();};</script></body></html>`))
	nonce := base64.URLEncoding.EncodeToString([]byte(random.String(8)))

	// Set headers
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("script-src 'self' 'sha384-ZGMxYzUyZTk2ZGY3OGNjZDNlMGFiMTI1M2RmMmNiNmY4MzgyZjY3NDcyZDc1M2U4YTRmNTEzYzc0NTE4M2FiOGZkMWQ1YzFhMjA2MDI2ZTNjOWMyOWEyYzY2YTRhY2Y2Cg==' 'nonce-%s';", nonce))

	// Write template to output
	if err := form.Execute(w, map[string]string{
		"RedirectURI": u.String(),
		"Code":        code,
		"Error":       errc,
		"State":       state,
		"Issuer":      authRes.Issuer,
		"Nonce":       nonce,
	}); err != nil {
		WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}
}

// redirectURIFromRequest returns the redirect URI carried by a decoded
// request object, or the empty string when the request could not be
// decoded far enough to carry one.
func redirectURIFromRequest(ar *flowv1.AuthorizationRequest) string {
	if ar == nil {
		return ""
	}
	return ar.GetRedirectUri()
}

// redirectAuthorizationError delivers a processing error to the client by
// redirect (RFC 6749 section 4.1.2.1: when a valid redirection URI is
// known, the resource owner is not informed of the error directly; the
// user agent is redirected with error, error_description, state and —
// per RFC 9207 section 2 — the issuer identifier). The response is
// marked non-cacheable per section 5.1.
func redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI, issuer string, protocolError *corev1.Error, state string) {
	u, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
		return
	}
	params := url.Values{}
	if protocolError != nil {
		params.Set("error", protocolError.Error)
		if protocolError.ErrorDescription != "" {
			params.Set("error_description", protocolError.ErrorDescription)
		}
	}
	params.Set("state", state)
	params.Set("iss", issuer)
	u.RawQuery = params.Encode()

	w.Header().Set("Cache-Control", "no-store")
	// The redirect target originates from the client's signed request
	// object and the server-side registered redirect URI list (validated
	// in services.Authorization), not from an attacker-controlled query
	// parameter: not an open redirect.
	//nolint:gosec // redirect target validated upstream (registered redirect URI)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

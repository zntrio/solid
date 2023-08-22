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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/dchest/uniuri"
	"gopkg.in/square/go-jose.v2"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/examples/authorizationserver/middleware"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/jwsreq"
	"zntr.io/solid/sdk/pairwise"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

// Authorization handles authorization HTTP requests.
func Authorization(issuer string, authz services.Authorization, clients storage.ClientReader, jarmEncoder jarm.ResponseEncoder, pairwiseEncoder pairwise.Encoder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only GET verb
		if r.Method != http.MethodGet {
			respond.WithError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
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
		sub, ok := middleware.Subject(ctx)
		if !ok || sub == "" {
			respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
			return
		}

		// Retrieve client
		client, err := clients.Get(ctx, clientID)
		if err != nil {
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Apply pairwise encoding
		if client.SubjectType == oidc.SubjectTypePairwise {
			sub, err = pairwiseEncoder.Encode(client.SectorIdentifier, sub)
			if err != nil {
				respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
				return
			}
		}

		// Prepare client request decoder
		clientRequestDecoder := jwsreq.AuthorizationRequestDecoder(jwt.DefaultVerifier(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
			var jwks jose.JSONWebKeySet
			if err := json.Unmarshal(client.Jwks, &jwks); err != nil {
				return nil, fmt.Errorf("unable to decode client JWKS")
			}

			// No error
			return &jwks, nil
		}, []string{"ES384"}))

		// Decode request
		ar, err := clientRequestDecoder.Decode(ctx, requestRaw)
		if err != nil {
			log.Println("unable to decode request:", err)
			respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
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
			respond.WithError(w, r, http.StatusBadRequest, res.Error)
			return
		}

		// Process according to response_mode
		switch res.ResponseMode {
		case oidc.ResponseTypeCode:
			responseTypeCode(w, r, res)
		case oidc.ResponseModeQueryJWT:
			responseTypeQueryJWT(w, r, res, jarmEncoder)
		case oidc.ResponseModeFragmentJWT:
			responseTypeFragmentJWT(w, r, res, jarmEncoder)
		case oidc.ResponseModeFormPOSTJWT:
			responseTypeFormPostJWT(w, r, res, jarmEncoder)
		default:
			responseTypeQueryJWT(w, r, res, jarmEncoder)
		}
	})
}

// -----------------------------------------------------------------------------

func responseTypeCode(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble final uri
	params := url.Values{}
	if authRes.Error != nil {
		params.Set("error", authRes.Error.Err)
		params.Set("state", authRes.State)
	} else {
		params.Set("code", authRes.Code)
		params.Set("iss", authRes.Issuer)
		params.Set("state", authRes.State)
	}

	// Assign new params
	u.RawQuery = params.Encode()

	// Redirect to application
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func responseTypeQueryJWT(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Encode JARM
	jarmToken, err := jarmEncoder.Encode(r.Context(), authRes.Issuer, authRes)
	if err != nil {
		log.Println("unable to produce JARM token:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble final uri
	params := url.Values{}
	params.Set("response", jarmToken)

	// Assign new params
	u.RawQuery = params.Encode()

	// Redirect to application
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func responseTypeFragmentJWT(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Encode JARM
	jarmToken, err := jarmEncoder.Encode(r.Context(), authRes.Issuer, authRes)
	if err != nil {
		log.Println("unable to produce JARM token:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Assemble final uri
	params := url.Values{}
	params.Set("response", jarmToken)

	// Assign new params
	u.Fragment = params.Encode()

	// Redirect to application
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func responseTypeFormPostJWT(w http.ResponseWriter, r *http.Request, authRes *flowv1.AuthorizeResponse, jarmEncoder jarm.ResponseEncoder) {
	// Build redirection uri
	u, err := url.ParseRequestURI(authRes.RedirectUri)
	if err != nil {
		log.Println("unable to process redirect uri:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Encode JARM
	jarmToken, err := jarmEncoder.Encode(r.Context(), authRes.Issuer, authRes)
	if err != nil {
		log.Println("unable to produce JARM token:", err)
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}

	// Prepare template
	form := template.Must(template.New("form-post-jwt").Parse(`<!DOCTYPE html><html><head><title>Submit This Form</title></head><body><form method="post" action="{{ .RedirectURI }}"><input type="hidden" name="response" value="{{ .Response }}"/></form><script type="text/javascript" nonce="{{ .Nonce }}" integrity="sha384-ZGMxYzUyZTk2ZGY3OGNjZDNlMGFiMTI1M2RmMmNiNmY4MzgyZjY3NDcyZDc1M2U4YTRmNTEzYzc0NTE4M2FiOGZkMWQ1YzFhMjA2MDI2ZTNjOWMyOWEyYzY2YTRhY2Y2Cg==">window.onload = function() {document.forms[0].submit();};</script></body></html>`))
	nonce := base64.URLEncoding.EncodeToString([]byte(uniuri.NewLen(8)))

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
		respond.WithError(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
		return
	}
}

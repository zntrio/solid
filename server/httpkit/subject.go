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
	"net/http"
	"strings"
)

type contextKey string

func (c contextKey) String() string {
	return "zntr.io/solid/server/httpkit/" + string(c)
}

var contextKeySubject = contextKey("subject")

// Subject returns the subject value bound to the context.
func Subject(ctx context.Context) (string, bool) {
	client, ok := ctx.Value(contextKeySubject).(string)
	return client, ok
}

var contextKeyAuthEvent = contextKey("auth_event")

// AuthenticationEvent describes the end-user authentication event observed
// by the presentation layer (RFC 9470 section 2: the login's acr and
// auth_time).
type AuthenticationEvent struct {
	// ACR is the authentication context class reference achieved by the
	// login (RFC 9470 section 6.2 / OIDC Core acr).
	ACR string
	// AuthTime is the unix timestamp of the authentication event
	// (RFC 9470 section 6.2 auth_time, seconds since epoch).
	AuthTime uint64
}

// AuthenticationEventFromContext returns the authentication event bound to
// the context, when the login surface recorded one.
func AuthenticationEventFromContext(ctx context.Context) (AuthenticationEvent, bool) {
	ev, ok := ctx.Value(contextKeyAuthEvent).(AuthenticationEvent)
	return ev, ok
}

// CredentialsChecker validates a username/password pair and returns the
// authenticated subject along with the observed authentication event, if any
// (a checker may authenticate a subject without asserting an ACR).
type CredentialsChecker func(username, password string) (subject string, event *AuthenticationEvent, ok bool)

// BasicAuthentication is a middleware to handle basic authentication.
// The credentials checker is supplied by the assembler; returning ok=false
// rejects the request with 401.
func BasicAuthentication(credentials CredentialsChecker) Adapter {
	unauthorized := func(rw http.ResponseWriter) {
		rw.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
		rw.WriteHeader(http.StatusUnauthorized)
	}

	// Return middleware
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			u, p, ok := r.BasicAuth()
			if !ok || len(strings.TrimSpace(u)) < 1 || len(strings.TrimSpace(p)) < 1 {
				unauthorized(w)
				return
			}

			// Delegate the credential decision to the assembler.
			subject, event, ok := credentials(u, p)
			if !ok {
				unauthorized(w)
				return
			}

			// Inject subject in context
			ctx = context.WithValue(ctx, contextKeySubject, subject)

			// RFC 9470 section 2: bind the login authentication event, when
			// the credentials checker observed one.
			if event != nil {
				ctx = context.WithValue(ctx, contextKeyAuthEvent, *event)
			}

			// Delegate to next handler
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

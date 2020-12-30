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
	"context"
	"net/http"
	"strings"
)

type contextKey string

func (c contextKey) String() string {
	return "zntr.io/solid/cmd/server/" + string(c)
}

var contextKeySubject = contextKey("subject")

// Subject returns the subject value bound to the context.
func Subject(ctx context.Context) (string, bool) {
	client, ok := ctx.Value(contextKeySubject).(string)
	return client, ok
}

// BasicAuthentication is a middleware to handle basic authentication.
func BasicAuthentication() Adapter {
	unauthorised := func(rw http.ResponseWriter) {
		rw.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
		rw.WriteHeader(http.StatusUnauthorized)
	}

	// Return middleware
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			u, p, ok := r.BasicAuth()
			if !ok || len(strings.TrimSpace(u)) < 1 || len(strings.TrimSpace(p)) < 1 {
				unauthorised(w)
				return
			}

			// This is a dummy check for credentials.
			if u != "hello" || p != "world" {
				unauthorised(w)
				return
			}

			// Inject subject in context
			ctx = context.WithValue(ctx, contextKeySubject, u)

			// Delegate to next handler
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

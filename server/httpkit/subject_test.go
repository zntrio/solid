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

package httpkit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"zntr.io/solid/server/httpkit"
)

// TestBasicAuthenticationBindsAuthenticationEvent asserts the Basic login
// middleware round-trips the credentials checker's authentication event
// (RFC 9470 section 2: acr + auth_time) into the request context, while a
// checker that asserts no ACR leaves the context without one.
func TestBasicAuthenticationBindsAuthenticationEvent(t *testing.T) {
	const demoACR = "urn:solid:loa:1fa:any"
	demoTime := uint64(1_700_000_000)

	t.Run("event bound when the checker returns one", func(t *testing.T) {
		handler := httpkit.BasicAuthentication(func(u, p string) (string, *httpkit.AuthenticationEvent, bool) {
			if u == "hello" && p == "world" {
				return u, &httpkit.AuthenticationEvent{ACR: demoACR, AuthTime: demoTime}, true
			}
			return "", nil, false
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub, ok := httpkit.Subject(r.Context())
			require.True(t, ok)
			require.Equal(t, "hello", sub)

			ev, ok := httpkit.AuthenticationEventFromContext(r.Context())
			require.True(t, ok, "authentication event must be bound to the context")
			require.Equal(t, demoACR, ev.ACR)
			require.Equal(t, demoTime, ev.AuthTime)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize", nil)
		req.SetBasicAuth("hello", "world")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("no event when the checker returns none", func(t *testing.T) {
		handler := httpkit.BasicAuthentication(func(u, p string) (string, *httpkit.AuthenticationEvent, bool) {
			return u, nil, true
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := httpkit.AuthenticationEventFromContext(r.Context())
			require.False(t, ok, "no authentication event must be bound")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize", nil)
		req.SetBasicAuth("hello", "world")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("invalid credentials rejected with 401", func(t *testing.T) {
		handler := httpkit.BasicAuthentication(func(u, p string) (string, *httpkit.AuthenticationEvent, bool) {
			return "", nil, false
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Fatal("next handler must not run on invalid credentials")
		}))

		req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize", nil)
		req.SetBasicAuth("hello", "nope")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

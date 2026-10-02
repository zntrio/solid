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
	"net/http/httptest"
	"testing"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/rfcerrors"
)

// Proves the RFC 6749 §4.1.2.1 error redirect carries the full parameter
// set (error, error_description, state, iss) and §5.1 no-store header.
func TestRedirectAuthorizationErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://as.example.com/authorize?x=1", nil)
	redirectAuthorizationError(rec, req, "https://client.example.org/cb",
		"https://as.example.com", rfcerrors.AccessDenied().Build(), "af0ifjsldkj")

	if rec.Code != 302 {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	for _, want := range []string{"error=access_denied", "error_description=", "state=af0ifjsldkj", "iss=https%3A%2F%2Fas.example.com"} {
		if !containsAll(loc, want) {
			t.Errorf("Location missing %q: %s", want, loc)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// Proves nil/undecodable requests fall back to direct JSON errors (no
// redirect target available).
func TestRedirectURIFromRequestNil(t *testing.T) {
	if got := redirectURIFromRequest(nil); got != "" {
		t.Errorf("nil request yields %q", got)
	}
	if got := redirectURIFromRequest(&flowv1.AuthorizationRequest{}); got != "" {
		t.Errorf("empty request yields %q", got)
	}
}

func containsAll(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || contains(s, sub))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Proves respond.WithError only emits WWW-Authenticate on 401 (RFC 6749
// §5.2) and carries Pragma: no-cache (§5.1).
func TestRespondErrorHeaderShape(t *testing.T) {
	// non-401: no challenge
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://as.example.com/token", nil)
	WithError(rec, req, 400, rfcerrors.InvalidRequest().Build())
	if wa := rec.Header().Get("WWW-Authenticate"); wa != "" {
		t.Errorf("400 response carries WWW-Authenticate: %q", wa)
	}
	if pr := rec.Header().Get("Pragma"); pr != "no-cache" {
		t.Errorf("Pragma = %q", pr)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	// 401: challenge present with realm
	rec2 := httptest.NewRecorder()
	WithError(rec2, req, 401, rfcerrors.InvalidClient().Build())
	if wa := rec2.Header().Get("WWW-Authenticate"); wa == "" {
		t.Error("401 response must carry WWW-Authenticate")
	}
}

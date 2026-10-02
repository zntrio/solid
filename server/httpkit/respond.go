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
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "zntr.io/solid/api/oidc/core/v1"
)

// WithError writes an RFC 6749 §5.2 JSON error response. The
// WWW-Authenticate challenge is only emitted on 401 invalid_client
// responses (§5.2: the authorization server MAY return an HTTP 401 with
// WWW-Authenticate matching the client authentication schemes it
// supports); other status codes carry the JSON error body alone.
// Responses are marked non-cacheable per §5.1 (Cache-Control: no-store
// and Pragma: no-cache).
func WithError(w http.ResponseWriter, r *http.Request, code int, err *corev1.Error) {
	// Marshal response as json
	body, _ := json.Marshal(err)

	// Set response as non cacheable (RFC 6749 §5.1; the 2.1 draft
	// keeps the Cache-Control MUST and drops Pragma — solid emits both
	// for maximal compatibility).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Set content type header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q, error=%q, error_description=%q`, r.Host, err.Error, err.ErrorDescription))
	}

	// Write status
	w.WriteHeader(code)

	// Write response
	_, _ = w.Write(body)
}

// WithJSON serialize the data with matching requested encoding
func WithJSON(w http.ResponseWriter, code int, data any) {
	// Marshal response as json
	body, _ := json.Marshal(data)
	// Set response as non cacheable (RFC 6749 §5.1: Cache-Control
	// no-store with the Pragma companion; the 2.1 draft keeps the
	// Cache-Control MUST and drops Pragma — solid emits both).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Set content type header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Write status
	w.WriteHeader(code)

	// Write response
	_, _ = w.Write(body)
}

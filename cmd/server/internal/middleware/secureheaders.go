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
	"net/http"
)

// SecurityHeaders is a middleware to add required security headers.
func SecurityHeaders() Adapter {
	// Return middleware
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Default security headers
			headers := map[string]string{
				"X-Frame-Options":         "DENY",
				"X-XSS-Protection":        "1; mode=block",
				"X-Content-Type-Options":  "nosniff",
				"Content-Security-Policy": "default-src 'none'",
				"Referrer-Policy":         "no-referrer",
				"X-Robots-Tag":            "noarchive",
				"Cache-Control":           "private, no-cache, must-revalidate",
			}

			// Add all headers
			for k, v := range headers {
				w.Header().Set(k, v)
			}

			// Delegate to next handler
			h.ServeHTTP(w, r)
		})
	}
}

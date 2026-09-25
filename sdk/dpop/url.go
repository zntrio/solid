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

package dpop

import (
	"fmt"
	"net/http"
)

// CleanURL returns a clean URL for a DPoP proof (htu claim). The scheme is
// derived from the actual transport: TLS or plain HTTP. The
// X-Forwarded-Scheme header is deliberately ignored because it is
// client-controlled and can be used to forge the htu value. Callers behind
// a reverse proxy MUST terminate TLS at the proxy or forward the absolute
// request URI so that the transport is reflected correctly.
func CleanURL(r *http.Request) string {
	// Prepare the url
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Assemble response
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
}

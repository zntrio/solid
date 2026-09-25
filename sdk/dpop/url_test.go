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
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
)

func TestCleanURL(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "plain http request",
			req:  &http.Request{Host: "server.example.com", URL: mustParse(t, "/resource")},
			want: "http://server.example.com/resource",
		},
		{
			name: "tls request",
			req:  &http.Request{Host: "server.example.com", URL: mustParse(t, "/resource"), TLS: fakeTLSState()},
			want: "https://server.example.com/resource",
		},
		{
			name: "X-Forwarded-Scheme header must not be trusted",
			req: func() *http.Request {
				r := &http.Request{Host: "server.example.com", URL: mustParse(t, "/resource")}
				r.Header = http.Header{}
				r.Header.Set("X-Forwarded-Scheme", "https")
				return r
			}(),
			want: "http://server.example.com/resource",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CleanURL(tt.req); got != tt.want {
				t.Errorf("CleanURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("unable to parse %q: %v", raw, err)
	}
	return u
}

func fakeTLSState() *tls.ConnectionState {
	return &tls.ConnectionState{}
}

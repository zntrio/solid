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

package cimd

import "testing"

func TestIsClientIdentifierURL(t *testing.T) {
	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "Empty", id: "", want: false},
		{name: "PlainHTTPS", id: "https://client.example.org/cimd.json", want: true},
		{name: "ExplicitDefaultPort", id: "https://client.example.org:443/cimd.json", want: true},
		{name: "CustomPort", id: "https://client.example.org:8443/cimd.json", want: true},
		{name: "HTTPScheme", id: "http://client.example.org/cimd.json", want: false},
		{name: "NoScheme", id: "client.example.org/cimd.json", want: false},
		{name: "Userinfo", id: "https://alice:secret@client.example.org/cimd.json", want: false},
		{name: "UserinfoOnly", id: "https://alice@client.example.org/cimd.json", want: false},
		{name: "NoPath", id: "https://client.example.org", want: false},
		{name: "RootPath", id: "https://client.example.org/", want: true},
		{name: "Fragment", id: "https://client.example.org/cimd.json#section", want: false},
		{name: "QueryAllowed", id: "https://client.example.org/cimd.json?foo=bar", want: true},
		{name: "SingleDotSegment", id: "https://client.example.org/./cimd.json", want: false},
		{name: "DoubleDotSegment", id: "https://client.example.org/../cimd.json", want: false},
		{name: "DotSegmentInMiddle", id: "https://client.example.org/a/../cimd.json", want: false},
		{name: "TrailingDoubleDot", id: "https://client.example.org/cimd.json/..", want: false},
		{name: "FilenameWithDots", id: "https://client.example.org/cimd.v2.json", want: true},
		{name: "DotInHostnameIsNotPath", id: "https://client.example.org/ok", want: true},
		{name: "Unparseable", id: "https://[::1", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsClientIdentifierURL(tc.id); got != tc.want {
				t.Errorf("IsClientIdentifierURL(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

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

package profile

import "zntr.io/solid/sdk/types"

// allows reports whether the application-type profile of the given client
// application type allows the value against the profile allowlist selected
// by list. An empty value imposes no constraint; an unknown application
// type (no profile entry) imposes no constraint either — the client
// registration metadata remains the gate.
func allows(s Server, applicationType, value string, list func(Client) types.StringArray) bool {
	if value == "" {
		return true
	}
	prof, ok := s.ApplicationType(applicationType)
	if !ok {
		return true
	}
	return list(prof).Contains(value)
}

// AllowsGrantType reports whether the application-type profile of the given
// client application type allows the grant type.
func AllowsGrantType(s Server, applicationType, grantType string) bool {
	return allows(s, applicationType, grantType, Client.GrantTypesSupported)
}

// AllowsResponseType reports whether the application-type profile of the
// given client application type allows the response type.
func AllowsResponseType(s Server, applicationType, responseType string) bool {
	return allows(s, applicationType, responseType, Client.ResponseTypesSupported)
}

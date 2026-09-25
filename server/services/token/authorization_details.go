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

package token

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// validateAuthorizationDetailsSubset enforces the RFC 9396 section 6
// comparison at the token endpoint: every requested authorization_details
// entry MUST be equal (proto equality) to one entry of the granted set.
// The comparison is deep and exact — a requested entry never grants more
// than what was consented.
func validateAuthorizationDetailsSubset(requested, granted []*tokenv1.AuthorizationDetail) error {
	for i, want := range requested {
		if want == nil {
			return fmt.Errorf("authorization_details[%d]: entry must not be null", i)
		}
		matched := false
		for _, have := range granted {
			if have != nil && proto.Equal(want, have) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("authorization_details[%d] of type %q was not consented in the authorization grant", i, want.Type)
		}
	}
	return nil
}

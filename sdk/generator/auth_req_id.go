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

package generator

import (
	"context"

	random "zntr.io/solid/sdk/random"
)

const (
	// DefaultAuthReqIDLen defines default CIBA auth_req_id length (32
	// alphanumeric chars ~ 190 bits of entropy, above the 160 bits
	// recommended by CIBA section 7.3).
	DefaultAuthReqIDLen = 32
)

// DefaultAuthReqID returns the default CIBA auth_req_id generator.
func DefaultAuthReqID() AuthReqID {
	return &authReqIDGenerator{}
}

// -----------------------------------------------------------------------------

type authReqIDGenerator struct{}

func (c *authReqIDGenerator) Generate(_ context.Context, _ string) (string, error) {
	return random.String(DefaultAuthReqIDLen), nil
}

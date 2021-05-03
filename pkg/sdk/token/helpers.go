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
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

// IsUsable check token usability constraint.
func IsUsable(t *corev1.Token) bool {
	// Check arguments
	if t == nil {
		return false
	}
	if t.Metadata == nil {
		return false
	}

	// Check expiration
	now := uint64(time.Now().Unix())
	if t.Metadata.ExpiresAt < now {
		return false
	}
	if t.Metadata.NotBefore > now {
		return false
	}

	// No error
	return true
}

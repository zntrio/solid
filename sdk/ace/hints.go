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

package ace

// EncodeASRequestCreationHints encodes the payload of a 4.01 (Unauthorized)
// response directing the client to the AS (RFC 9200 section 5.3, Table 1):
// AS=1, audience=5, scope=9; empty members are omitted.
func EncodeASRequestCreationHints(as, audience, scope string) []byte {
	hints := map[int]any{}
	if as != "" {
		hints[KeyAS] = as
	}
	if audience != "" {
		hints[KeyAudience] = audience
	}
	if scope != "" {
		hints[KeyScope] = scope
	}

	return encodeMap(hints)
}

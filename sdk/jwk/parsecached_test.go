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

package jwk

import (
	"testing"
)

const es256JWKSFixture = `{"keys":[{"kty":"EC","crv":"P-256","x":"bzPOh-UArc5jiOK2_xe7Z9Cwf1Far845IDMNoPLIUUs","y":"aeupyw4SC0t0EzAo27V2K2EihqxTBPSUts3Uhrdweak","alg":"ES256","use":"sig"}]}`

func TestParseCachedSameBytesReturnSameSet(t *testing.T) {
	set1, err := ParseCached([]byte(es256JWKSFixture))
	if err != nil {
		t.Fatalf("ParseCached: %v", err)
	}
	set2, err := ParseCached([]byte(es256JWKSFixture))
	if err != nil {
		t.Fatalf("ParseCached (second call): %v", err)
	}
	if set1 != set2 {
		t.Fatal("identical JWKS bytes must return the memoized Set pointer")
	}
	if set2.Len() != 1 {
		t.Fatalf("cached set must hold 1 key, got %d", set2.Len())
	}
}

func TestParseCachedRotationReparse(t *testing.T) {
	set1, err := ParseCached([]byte(es256JWKSFixture))
	if err != nil {
		t.Fatalf("ParseCached: %v", err)
	}
	// A rotated (different-bytes) JWKS must NOT return the stale set.
	rotated := `{"keys":[{"kty":"EC","crv":"P-256","x":"BZ6Y_Ukw8A5dGA1c29XBAmXJK6at28w6xYrhS4QG9rw","y":"v29JC1wXG-PbjGkJOb5gaYL5bxu1kDWqyTMKuvlZ3Qc","alg":"ES256","use":"sig"}]}`
	set2, err := ParseCached([]byte(rotated))
	if err != nil {
		t.Fatalf("ParseCached (rotated): %v", err)
	}
	if set1 == set2 {
		t.Fatal("different JWKS bytes must re-parse, not return the stale set")
	}
}

func TestParseCachedErrorsNotCached(t *testing.T) {
	if _, err := ParseCached([]byte(`not-json`)); err == nil {
		t.Fatal("malformed document must fail")
	}
	// The failed parse must not be memoized: the same bad bytes fail again.
	if _, err := ParseCached([]byte(`not-json`)); err == nil {
		t.Fatal("failed parses must not be cached as successes")
	}
}

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

package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func errNew(msg string) error { return errors.New(msg) }

func rawURLDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// nowUnix returns the current time; indirection keeps the KB-JWT iat
// fresh relative to the wall clock the verifier uses.
func nowUnix(t *testing.T) int64 {
	t.Helper()
	return time.Now().Unix()
}
func unmarshalJSON(b []byte, v any) error { return json.Unmarshal(b, v) }

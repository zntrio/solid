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

package verifiable

import (
	"fmt"
	"math/big"
	"strings"
)

// https://ucarion.com/go-base62

func toPaddedBase62(input []byte, length int) string {
	var i big.Int
	i.SetBytes(input)
	return padLeft(i.Text(62), length)
}

func padLeft(in string, length int) string {
	if len(in) < length {
		in = strings.Repeat("0", length-len(in)) + in
	}

	return in
}

func parsePaddedBase62(s string, length int) ([]byte, error) {
	out := make([]byte, length)

	var i big.Int
	_, ok := i.SetString(s, 62)
	if !ok {
		return []byte{}, fmt.Errorf("cannot parse base62: %q", s)
	}

	return i.FillBytes(out), nil
}

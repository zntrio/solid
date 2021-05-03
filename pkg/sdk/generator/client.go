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

	"github.com/dchest/uniuri"
)

const (
	// DefaultClientIDLen defines default client id length.
	DefaultClientIDLen = 16
)

// DefaultClientID returns the default client id generator.
func DefaultClientID() ClientID {
	return &clientIDGenerator{}
}

// -----------------------------------------------------------------------------

type clientIDGenerator struct{}

func (c *clientIDGenerator) Generate(_ context.Context) (string, error) {
	code := uniuri.NewLen(DefaultClientIDLen)
	return code, nil
}

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
	"errors"
	"regexp"
	"strings"

	random "zntr.io/solid/sdk/random"
)

const (
	// DefaultRequestURILen defines default request_uri length.
	DefaultRequestURILen = 32
)

var requestURIMatcher = regexp.MustCompile(`urn:solid:[A-Za-z0-9]{32}`)

// DefaultRequestURI returns the default request uri generator.
func DefaultRequestURI() RequestURI {
	return &requestURIGenerator{}
}

// -----------------------------------------------------------------------------

type requestURIGenerator struct{}

func (c *requestURIGenerator) Generate(_ context.Context, _ string) (string, error) {
	// RFC 9126 section 2.1: the request_uri value is a URI; the solid
	// profile uses the urn:solid: URN namespace accepted by Validate.
	return "urn:solid:" + random.String(DefaultRequestURILen), nil
}

func (c *requestURIGenerator) Validate(_ context.Context, issuer, in string) error {
	// Normalize
	in = strings.TrimSpace(in)

	// Check format
	if !requestURIMatcher.MatchString(in) {
		return errors.New("invalid request_uri syntax")
	}

	// No error
	return nil
}

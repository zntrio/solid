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
	"errors"
	"regexp"
)

var (
	defaultSeparator   = "_"
	nonAuthorizedChars = regexp.MustCompile("[^a-z0-9-]")
)

// ErrTokenNotAuthenticated is raised when you try to validate a non compliant value.
var ErrTokenNotAuthenticated = errors.New("token: value could not be authenticated")

// Generator describes token generator contract.
type Generator interface {
	Generate(...GenerateOption) (string, error)
}

// Verifier describes token verification contract.
type Verifier interface {
	Verify(t string) error
}

// Extractor describes content extractor for wrapped values.
type Extractor[T any] interface {
	Extract(t string) (T, error)
}

type VerifiableGenerator interface {
	Generator
	Verifier
}

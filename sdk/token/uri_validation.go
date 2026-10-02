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
	"net/url"

	"github.com/go-ozzo/ozzo-validation/v4"
)

// ErrValidateURI is the error returned by the ValidateURI rule.
var ErrValidateURI = validation.NewError("validation_is_uri", "must be a valid URI")

// ValidateURI is a validation rule asserting an absolute URI with a scheme
// and an authority (RFC 3986 generic syntax). It replaces is.URL for issuer
// and audience identifiers: the OAuth ecosystem registers non-HTTP scheme
// identifiers (coaps:// for ACE over CoAP/DTLS, RFC 9200 section 5.2;
// device: and tag: URNs), which an HTTP-centric URL allowlist would wrongly
// reject while a transport-agnostic SDK must accept them.
var ValidateURI = validation.NewStringRuleWithError(validateAbsoluteURI, ErrValidateURI)

// validateAbsoluteURI reports whether str parses as an absolute URI with
// both a scheme and a host component and no fragment.
func validateAbsoluteURI(str string) bool {
	u, err := url.Parse(str)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Fragment != "" {
		return false
	}
	return true
}

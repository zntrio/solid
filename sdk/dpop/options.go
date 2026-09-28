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

package dpop

// -----------------------------------------------------------------------------

type options struct {
	tokenValue        *string
	tokenConfirmation *string
	expectedNonce     *string
}

type Option func(*options)

func WithTokenValue(t string) func(opts *options) {
	return func(opts *options) {
		opts.tokenValue = &t
	}
}

func WithTokenConfirmation(jkt string) func(opts *options) {
	return func(opts *options) {
		opts.tokenConfirmation = &jkt
	}
}

// WithExpectedNonce pins the nonce value the proof MUST carry (RFC 9449
// section 4.3): when set, the verifier rejects proofs whose nonce claim is
// absent or differs. Servers issue the value in a DPoP-Nonce response
// header and clients echo it in the proof nonce claim.
func WithExpectedNonce(nonce string) func(opts *options) {
	return func(opts *options) {
		opts.expectedNonce = &nonce
	}
}

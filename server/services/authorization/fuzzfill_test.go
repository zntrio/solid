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

package authorization

import (
	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// fuzzStr derives a deterministic string from seed bytes at the given offset.
func fuzzStr(seed []byte, offset int, maxLen int) string {
	if len(seed) == 0 || offset >= len(seed) {
		return ""
	}
	n := int(seed[offset]) % maxLen
	out := make([]byte, 0, n)
	for i := range n {
		out = append(out, seed[(offset+i)%len(seed)])
	}
	return string(out)
}

// fuzzPtrStr derives a deterministic *string from seed bytes.
func fuzzPtrStr(seed []byte, offset int, maxLen int) *string {
	if len(seed) == 0 || offset >= len(seed) {
		return nil
	}
	v := fuzzStr(seed, offset, maxLen)
	return &v
}

// fuzzFillAuthorizationRequest deterministically derives an AuthorizationRequest
// from pseudo-random bytes, for panic-only smoke fuzzing.
func fuzzFillAuthorizationRequest(seed []byte) *flowv1.AuthorizationRequest {
	req := &flowv1.AuthorizationRequest{
		Scope:               fuzzStr(seed, 0, 128),
		ResponseType:        fuzzStr(seed, 1, 32),
		ClientId:            fuzzStr(seed, 2, 64),
		RedirectUri:         fuzzStr(seed, 3, 128),
		State:               fuzzStr(seed, 4, 64),
		ResponseMode:        fuzzPtrStr(seed, 5, 32),
		Nonce:               fuzzStr(seed, 6, 64),
		Display:             fuzzPtrStr(seed, 7, 16),
		Prompt:              fuzzPtrStr(seed, 8, 32),
		UiLocales:           fuzzPtrStr(seed, 9, 64),
		IdTokenHint:         fuzzPtrStr(seed, 10, 128),
		AcrValues:           fuzzPtrStr(seed, 11, 64),
		Request:             fuzzPtrStr(seed, 12, 256),
		RequestUri:          fuzzPtrStr(seed, 13, 128),
		CodeChallenge:       fuzzStr(seed, 14, 96),
		CodeChallengeMethod: fuzzStr(seed, 15, 16),
		Audience:            fuzzStr(seed, 16, 128),
		DpopProof:           fuzzPtrStr(seed, 17, 512),
	}
	if len(seed) > 18 {
		maxAge := uint64(seed[18])
		req.MaxAge = &maxAge
	}
	return req
}

// fuzzFillAuthorizeRequest deterministically derives an AuthorizeRequest from
// pseudo-random bytes, for panic-only smoke fuzzing.
func fuzzFillAuthorizeRequest(seed []byte) *flowv1.AuthorizeRequest {
	return &flowv1.AuthorizeRequest{
		Issuer:  fuzzStr(seed, 19, 128),
		Client:  fuzzFillClient(seed),
		Subject: fuzzStr(seed, 20, 64),
		Request: fuzzFillAuthorizationRequest(seed),
	}
}

// fuzzFillRegistrationRequest deterministically derives a RegistrationRequest
// from pseudo-random bytes, for panic-only smoke fuzzing.
func fuzzFillRegistrationRequest(seed []byte) *flowv1.RegistrationRequest {
	return &flowv1.RegistrationRequest{
		Issuer:  fuzzStr(seed, 19, 128),
		Client:  fuzzFillClient(seed),
		Request: fuzzFillAuthorizationRequest(seed),
	}
}

// fuzzFillClient deterministically derives a Client from pseudo-random bytes.
func fuzzFillClient(seed []byte) *clientv1.Client {
	if len(seed) == 0 {
		return nil
	}
	return &clientv1.Client{
		ClientId:                fuzzStr(seed, 21, 64),
		GrantTypes:              []string{fuzzStr(seed, 22, 32)},
		ResponseTypes:           []string{fuzzStr(seed, 23, 16)},
		RedirectUris:            []string{fuzzStr(seed, 24, 128)},
		SectorIdentifier:        fuzzStr(seed, 26, 128),
		SubjectType:             fuzzStr(seed, 27, 16),
		TokenEndpointAuthMethod: fuzzStr(seed, 28, 32),
	}
}

// fuzzFillTokenConfirmation deterministically derives a TokenConfirmation from
// pseudo-random bytes.
func fuzzFillTokenConfirmation(seed []byte) *tokenv1.TokenConfirmation {
	if len(seed) == 0 {
		return nil
	}
	return &tokenv1.TokenConfirmation{
		Jkt: fuzzStr(seed, 29, 128),
	}
}

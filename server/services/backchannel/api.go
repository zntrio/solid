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

// Package backchannel implements the OpenID Client-Initiated
// Backchannel Authentication (CIBA) Core 1.0 backchannel
// authentication service: bc-authorize request processing, and the
// end-user approval channel on the authentication device.
package backchannel

import (
	"context"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
)

// HintResolver resolves exactly one of the CIBA hints (login_hint,
// login_hint_token, id_token_hint) to the end-user subject. Hint semantics
// are deployment-specific (CIBA section 7.2 step 4); a failing resolver
// yields unknown_user_id.
type HintResolver interface {
	Resolve(ctx context.Context, req *flowv1.BackchannelAuthenticationRequest) (string, error)
}

// HintResolverFunc adapts a function to HintResolver.
type HintResolverFunc func(ctx context.Context, req *flowv1.BackchannelAuthenticationRequest) (string, error)

// Resolve implements HintResolver.
func (f HintResolverFunc) Resolve(ctx context.Context, req *flowv1.BackchannelAuthenticationRequest) (string, error) {
	return f(ctx, req)
}

// LoginHintResolver treats login_hint as the subject identifier: identity
// mapping is a deployment concern, so the default resolver delegates it.
func LoginHintResolver() HintResolver {
	return HintResolverFunc(func(_ context.Context, req *flowv1.BackchannelAuthenticationRequest) (string, error) {
		if hint := req.GetLoginHint(); hint != "" {
			return hint, nil
		}
		if hint := req.GetLoginHintToken(); hint != "" {
			return hint, nil
		}
		if hint := req.GetIdTokenHint(); hint != "" {
			return hint, nil
		}
		return "", nil
	})
}

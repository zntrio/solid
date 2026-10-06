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
	"fmt"
	"strings"
	"time"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
)

// timeFunc allows tests to freeze the clock (same pattern as
// server/services/token/generator.go line 37).
var timeFunc = time.Now

// validateStepUpRequirements enforces the RFC 9470 section 4/5
// authorization request parameters (acr_values, max_age) against the
// authentication event recorded for the login.
func validateStepUpRequirements(req *flowv1.AuthorizationRequest, ev *tokenv1.AuthEvent) (*corev1.Error, error) {
	// Every violation surfaces the same protocol error; only the cause
	// message differs.
	unmet := func(format string, a ...any) (*corev1.Error, error) {
		return rfcerrors.UnmetAuthenticationRequirements().State(req.State).Build(),
			fmt.Errorf(format, a...)
	}

	// ACR enforcement (RFC 9470 section 5 + OIDC Core section 5.5.1.1,
	// defensive posture — this profile has no interactive re-auth
	// surface, so an unmeetable ACR fails immediately instead of
	// minting a token the resource server will reject):
	if req.AcrValues != nil && *req.AcrValues != "" {
		if ev == nil || ev.Acr == nil {
			return unmet("acr_values requested but no authentication context recorded for the login")
		}
		requested := types.StringArray(strings.Fields(*req.AcrValues))
		if !requested.Contains(*ev.Acr) {
			return unmet("requested acr_values %q do not include the achieved acr %q", *req.AcrValues, *ev.Acr)
		}
	}

	// max_age enforcement (RFC 9470 section 5: the login must be recent
	// enough). now == auth_time+max_age passes (elapsed == allowed).
	if req.MaxAge != nil {
		if ev == nil || ev.AuthTime == nil || *ev.AuthTime == 0 {
			return unmet("max_age requested but no authentication time recorded for the login")
		}
		if uint64(timeFunc().Unix()) > *ev.AuthTime+*req.MaxAge { //nolint:gosec // unix time is non-negative
			return unmet("the authentication event is older than the requested max_age %d", *req.MaxAge)
		}
	}

	return nil, nil
}
